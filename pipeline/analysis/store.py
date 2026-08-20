"""Persist static analysis results and roll them up against events.

:mod:`pipeline.analysis.static` is deliberately a pure function over bytes — it
imports no database and knows nothing about events. This module is the seam:
it reads the payload store, runs the analyser, and writes rows that the API can
join back to the sessions that carried each artefact.

    python -m pipeline.analysis.store              # analyse anything new
    python -m pipeline.analysis.store --reanalyse  # redo everything

Re-running is always safe. The ``payloads`` table is derived from the bytes on
disk the same way ``attackers`` is derived from events, so dropping it and
rescanning loses nothing. By default an artefact whose row already exists is
skipped, because analysis is the expensive part and the bytes cannot change —
the hash *is* the content. ``--reanalyse`` exists for when the analyser itself
has improved, which is the only thing that makes an existing row stale.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from pipeline.analysis.static import DEFAULT_PAYLOAD_DIR, analyze_file
from storage.models import Event, Payload, ensure_utc, utcnow

log = logging.getLogger("pipeline.analysis.store")


def _rollup(db: OrmSession, sha256: str) -> dict[str, Any]:
    """First seen, last seen and event count for one artefact.

    An artefact can arrive with no matching event — someone drops a file into
    the payload directory by hand, or the event was pruned by retention. That
    is not an error: the analysis still stands on its own, the row simply has
    no sightings attached.
    """
    row = db.execute(
        select(
            func.min(Event.ts),
            func.max(Event.ts),
            func.count(Event.id),
        ).where(Event.payload_sha256 == sha256)
    ).one()
    first, last, count = row
    return {
        "first_seen": ensure_utc(first),
        "last_seen": ensure_utc(last),
        "event_count": int(count or 0),
    }


def store_analysis(db: OrmSession, result: dict[str, Any]) -> Payload:
    """Upsert one analyser result, rolled up against the events that carried it."""
    sha256 = result["sha256"]
    payload = db.get(Payload, sha256) or Payload(sha256=sha256)

    payload.size = result.get("size", 0)
    payload.file_type = result.get("file_type")
    payload.mime = result.get("mime")
    payload.arch = result.get("arch")
    payload.linkage = result.get("linkage")
    payload.stripped = result.get("stripped")
    payload.entropy = result.get("entropy", 0.0)
    payload.likely_packed = bool(result.get("likely_packed"))
    payload.strings_count = result.get("strings_count", 0)
    payload.behaviour_tags = list(result.get("behaviour_tags") or [])
    payload.yara_matches = list(result.get("yara_matches") or [])
    # Stored exactly as the analyser returned them, which means defanged.
    payload.iocs = dict(result.get("iocs") or {})
    payload.format_details = dict(result.get("format_details") or {})
    payload.analyzed_at = utcnow()

    for key, value in _rollup(db, sha256).items():
        setattr(payload, key, value)

    db.add(payload)
    return payload


def scan_and_store(
    db: OrmSession,
    directory: str | Path | None = None,
    *,
    reanalyse: bool = False,
    limit: int | None = None,
) -> dict[str, int]:
    """Analyse the payload store and persist the results.

    Returns counts of what happened. Files that cannot be read are counted and
    logged rather than raised: one unreadable artefact must not abandon the
    rest of the scan.
    """
    directory = Path(directory or DEFAULT_PAYLOAD_DIR)
    stats = {"seen": 0, "analysed": 0, "skipped": 0, "errors": 0}
    if not directory.is_dir():
        log.info("no payload directory at %s; nothing to do", directory)
        return stats

    known: set[str] = set()
    if not reanalyse:
        known = set(db.execute(select(Payload.sha256)).scalars())

    paths = sorted(directory.glob("*.bin"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in paths[:limit] if limit else paths:
        stats["seen"] += 1
        # Files are named by content hash, so the stem is the identity — no
        # need to read a file whose analysis is already current.
        if not reanalyse and path.stem in known:
            stats["skipped"] += 1
            continue
        try:
            result = analyze_file(path)
        except OSError as exc:
            stats["errors"] += 1
            log.warning("could not read %s: %s", path.name, exc)
            continue
        store_analysis(db, result)
        stats["analysed"] += 1

    return stats


def refresh_rollups(db: OrmSession) -> int:
    """Recompute sighting counts for every stored payload.

    Cheap, and worth running after importing historical logs: the analysis of
    an artefact does not change, but which events point at it does.
    """
    updated = 0
    for payload in db.execute(select(Payload)).scalars():
        for key, value in _rollup(db, payload.sha256).items():
            setattr(payload, key, value)
        updated += 1
    return updated


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Analyse captured payloads and store the results. Never executes a sample."
    )
    parser.add_argument("--dir", help=f"payload directory (default: {DEFAULT_PAYLOAD_DIR})")
    parser.add_argument(
        "--reanalyse",
        action="store_true",
        help="re-run artefacts that already have a row (use after improving the analyser)",
    )
    parser.add_argument("--limit", type=int, help="stop after N files")
    parser.add_argument(
        "--refresh-rollups",
        action="store_true",
        help="only recompute event counts for existing rows",
    )
    args = parser.parse_args(argv)

    from storage.db import session_scope

    with session_scope() as db:
        if args.refresh_rollups:
            count = refresh_rollups(db)
            db.commit()
            print(f"refreshed {count} payload rollup(s)")
            return 0

        stats = scan_and_store(db, args.dir, reanalyse=args.reanalyse, limit=args.limit)
        db.commit()

    print(
        f"seen {stats['seen']}, analysed {stats['analysed']}, "
        f"skipped {stats['skipped']}, errors {stats['errors']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["store_analysis", "scan_and_store", "refresh_rollups"]
