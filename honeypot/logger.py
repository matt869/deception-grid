"""Event sink for the honeypot.

The honeypot runs on asyncio and must never block its event loop on disk or
database I/O — a slow fsync while holding the loop would stall every other live
connection and change the sensor's timing fingerprint. So ``emit()`` only puts a
dict on a bounded queue and returns; a single background thread drains it and
writes in batches.

The queue is *bounded on purpose*. If a flood outruns the writer, dropping the
overflow and counting it is strictly better than growing until the process is
OOM-killed and the whole sensor goes dark. ``dropped`` is reported in the stats
line so silent loss is impossible.
"""

from __future__ import annotations

import hashlib
import json
import logging
import queue
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

from honeypot.config import Settings
from storage.models import Event, Session, Severity, utcnow

log = logging.getLogger("honeypot.logger")

_QUEUE_MAXSIZE = 10_000
_BATCH_SIZE = 100
_BATCH_TIMEOUT_S = 1.0

_SENTINEL = object()


class EventLogger:
    """Batching, non-blocking writer for events and sessions."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._queue: queue.Queue = queue.Queue(maxsize=_QUEUE_MAXSIZE)
        self._thread: Optional[threading.Thread] = None
        self._running = threading.Event()
        self._jsonl_handle = None

        self.written = 0
        self.dropped = 0
        self.errors = 0

        self._enricher = None
        if settings.enrich_inline:
            # Imported lazily so the honeypot still starts if the optional
            # enrichment dependencies are missing.
            try:
                from pipeline.enrichment import enrich_event

                self._enricher = enrich_event
            except Exception as exc:  # pragma: no cover - defensive
                log.warning("inline enrichment unavailable (%s); continuing without", exc)

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self) -> None:
        if self._thread is not None:
            return
        if self.settings.jsonl_path is not None:
            self.settings.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
            self._jsonl_handle = open(self.settings.jsonl_path, "a", encoding="utf-8")

        self._running.set()
        self._thread = threading.Thread(target=self._run, name="event-writer", daemon=True)
        self._thread.start()
        log.info("event writer started (db=%s jsonl=%s)", self.settings.write_to_db,
                 self.settings.jsonl_path)

    def stop(self, timeout: float = 10.0) -> None:
        """Signal the writer to drain and exit."""
        if self._thread is None:
            return
        self._running.clear()
        try:
            self._queue.put_nowait(_SENTINEL)
        except queue.Full:
            pass
        self._thread.join(timeout=timeout)
        self._thread = None
        if self._jsonl_handle is not None:
            self._jsonl_handle.close()
            self._jsonl_handle = None
        log.info(
            "event writer stopped (written=%d dropped=%d errors=%d)",
            self.written, self.dropped, self.errors,
        )

    def __enter__(self) -> "EventLogger":
        self.start()
        return self

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # ------------------------------------------------------------------ #
    # Producer side (called from the asyncio loop)
    # ------------------------------------------------------------------ #

    def emit(self, event: dict[str, Any]) -> bool:
        """Queue one event. Returns False if it was dropped."""
        event.setdefault("event_id", str(uuid.uuid4()))
        event.setdefault("ts", utcnow())
        event.setdefault("sensor", self.settings.sensor_name)
        event.setdefault("severity", Severity.INFO.value)

        if self.settings.hash_passwords and event.get("password"):
            event["password"] = "sha256:" + hashlib.sha256(
                event["password"].encode("utf-8", "replace")
            ).hexdigest()[:32]

        try:
            self._queue.put_nowait(("event", event))
            return True
        except queue.Full:
            self.dropped += 1
            if self.dropped % 100 == 1:
                log.warning("event queue full; dropped %d events so far", self.dropped)
            return False

    def emit_session(self, session: dict[str, Any]) -> bool:
        """Queue a session upsert (start or end)."""
        try:
            self._queue.put_nowait(("session", session))
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def save_payload(self, data: bytes) -> Optional[str]:
        """Write a captured payload to disk, keyed by content hash.

        Returns the sha256 hex digest, or None if capture is disabled. Storing
        by hash means the same dropper uploaded a thousand times costs one file.
        """
        if not self.settings.capture_payloads or not data:
            return None
        digest = hashlib.sha256(data).hexdigest()
        path: Path = self.settings.payload_dir / f"{digest}.bin"
        if not path.exists():
            try:
                path.write_bytes(data)
            except OSError as exc:  # pragma: no cover - disk full etc.
                log.error("failed to persist payload %s: %s", digest[:12], exc)
                return digest
        return digest

    def stats(self) -> dict[str, int]:
        return {
            "written": self.written,
            "dropped": self.dropped,
            "errors": self.errors,
            "queued": self._queue.qsize(),
        }

    # ------------------------------------------------------------------ #
    # Consumer side (background thread)
    # ------------------------------------------------------------------ #

    def _run(self) -> None:
        batch: list[tuple[str, dict[str, Any]]] = []
        while True:
            try:
                item = self._queue.get(timeout=_BATCH_TIMEOUT_S)
            except queue.Empty:
                if batch:
                    self._flush(batch)
                    batch = []
                if not self._running.is_set():
                    break
                continue

            if item is _SENTINEL:
                if batch:
                    self._flush(batch)
                self._drain_remaining()
                break

            batch.append(item)
            if len(batch) >= _BATCH_SIZE:
                self._flush(batch)
                batch = []

    def _drain_remaining(self) -> None:
        leftover: list[tuple[str, dict[str, Any]]] = []
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            if item is not _SENTINEL:
                leftover.append(item)
        if leftover:
            self._flush(leftover)

    def _flush(self, batch: list[tuple[str, dict[str, Any]]]) -> None:
        events = [payload for kind, payload in batch if kind == "event"]
        sessions = [payload for kind, payload in batch if kind == "session"]

        if self._enricher is not None:
            for event in events:
                try:
                    self._enricher(event)
                except Exception as exc:  # pragma: no cover - enrichment is best-effort
                    log.debug("enrichment failed for %s: %s", event.get("src_ip"), exc)

        if self._jsonl_handle is not None:
            self._write_jsonl(events)

        if self.settings.write_to_db:
            self._write_db(events, sessions)

        self.written += len(events)

    def _write_jsonl(self, events: list[dict[str, Any]]) -> None:
        try:
            for event in events:
                self._jsonl_handle.write(json.dumps(event, default=str) + "\n")
            self._jsonl_handle.flush()
        except OSError as exc:  # pragma: no cover
            self.errors += 1
            log.error("jsonl write failed: %s", exc)

    def _write_db(self, events: list[dict[str, Any]], sessions: list[dict[str, Any]]) -> None:
        from storage.db import session_scope

        try:
            with session_scope() as db:
                # Sessions first: events carry a FK to session_id.
                for payload in sessions:
                    sid = payload.get("session_id")
                    if not sid:
                        continue
                    row = db.get(Session, sid)
                    if row is None:
                        row = Session(session_id=sid)
                    for key, value in payload.items():
                        if hasattr(row, key):
                            setattr(row, key, value)
                    db.add(row)
                db.flush()

                for payload in events:
                    db.add(Event(**_project(payload, Event)))
        except Exception as exc:
            self.errors += 1
            log.error("db write failed for %d events: %s", len(events), exc, exc_info=True)


def _project(payload: dict[str, Any], model) -> dict[str, Any]:
    """Drop keys that are not columns on ``model``.

    Services are free to attach extra diagnostic keys to an event dict; anything
    unrecognised is folded into ``extra`` rather than raising.
    """
    columns = {c.name for c in model.__table__.columns}
    kept = {k: v for k, v in payload.items() if k in columns}
    leftovers = {k: v for k, v in payload.items() if k not in columns}
    if leftovers:
        merged = dict(kept.get("extra") or {})
        merged.update(leftovers)
        kept["extra"] = merged
    return kept


def configure_logging(level: str = "INFO") -> None:
    """Console logging for the honeypot process itself (not attacker events)."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)-24s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # asyncio logs a warning for every client that resets the connection, which
    # for a honeypot is the normal case, not an anomaly.
    logging.getLogger("asyncio").setLevel(logging.ERROR)


__all__ = ["EventLogger", "configure_logging"]
