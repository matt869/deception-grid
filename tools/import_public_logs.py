"""Import honeypot logs recorded elsewhere.

    python -m tools.import_public_logs --format cowrie data/public_logs/cowrie.json
    python -m tools.import_public_logs --format auth-log /var/log/auth.log
    python -m tools.import_public_logs --format jsonl data/events.jsonl

Supported inputs:

``cowrie``    Cowrie's JSON log — the most widely published honeypot format, so
              public research datasets usually arrive this way.
``jsonl``     This project's own JSONL sink, for replaying a sensor's output
              into a fresh database.
``auth-log``  Linux ``/var/log/auth.log``. Not honeypot data — this is your real
              SSH server's failed-login record, which is genuinely useful to
              compare against sensor traffic.

Imported rows are stamped with ``sensor`` set to the source name and
``extra.imported_from`` set to the file, so imported history is always
distinguishable from what your own sensor observed. That matters the moment
somebody asks "did we actually see this?"

**On importing other people's logs:** public honeypot datasets contain real
source addresses belonging to real, often compromised, third-party machines, and
frequently real credentials. Treat an imported dataset with the same care as
your own capture — see docs/event_schema.md.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from pipeline.enrichment import enrich_event
from storage.db import init_db, session_scope
from storage.models import Event, EventType, Session, Severity, utcnow

# --------------------------------------------------------------------------- #
# Cowrie
# --------------------------------------------------------------------------- #

COWRIE_EVENT_MAP = {
    "cowrie.session.connect": (EventType.CONNECT, Severity.INFO),
    "cowrie.login.failed": (EventType.AUTH_ATTEMPT, Severity.MEDIUM),
    "cowrie.login.success": (EventType.AUTH_SUCCESS, Severity.HIGH),
    "cowrie.command.input": (EventType.COMMAND, Severity.HIGH),
    "cowrie.command.failed": (EventType.COMMAND, Severity.MEDIUM),
    "cowrie.session.file_download": (EventType.FILE_UPLOAD, Severity.CRITICAL),
    "cowrie.session.file_upload": (EventType.FILE_UPLOAD, Severity.CRITICAL),
    "cowrie.session.closed": (EventType.DISCONNECT, Severity.INFO),
    "cowrie.client.version": (EventType.CONNECT, Severity.LOW),
    "cowrie.direct-tcpip.request": (EventType.CONNECT, Severity.HIGH),
}


def parse_cowrie(path: Path, sensor: str) -> Iterator[dict[str, Any]]:
    """Yield event dicts from a Cowrie JSON log (one JSON object per line)."""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # Cowrie logs are sometimes truncated mid-write on rotation.
                # One bad line should not abort a million-line import.
                continue

            eventid = record.get("eventid", "")
            mapped = COWRIE_EVENT_MAP.get(eventid)
            if mapped is None:
                continue
            event_type, severity = mapped

            ts = _parse_timestamp(record.get("timestamp"))
            if ts is None:
                continue

            # Cowrie's protocol field is 'ssh' or 'telnet'.
            service = record.get("protocol") or ("telnet" if "telnet" in eventid else "ssh")

            event: dict[str, Any] = {
                "event_id": str(uuid.uuid4()),
                "ts": ts,
                "sensor": sensor,
                "session_id": record.get("session") or str(uuid.uuid4()),
                "service": service,
                "event_type": event_type.value,
                "severity": severity.value,
                "src_ip": record.get("src_ip") or "0.0.0.0",
                "src_port": _int_or_none(record.get("src_port")),
                "dst_port": _int_or_none(record.get("dst_port")),
                "username": record.get("username"),
                "password": record.get("password"),
                "command": record.get("input"),
                "payload_sha256": record.get("shasum"),
                "payload_size": _int_or_none(record.get("size")) or 0,
                "tags": _cowrie_tags(record, eventid),
                "extra": {
                    "imported_from": path.name,
                    "cowrie_eventid": eventid,
                    "client_version": record.get("version"),
                    "url": record.get("url"),
                },
            }
            yield event


def _cowrie_tags(record: dict[str, Any], eventid: str) -> list[str]:
    tags = [f"cowrie:{eventid.split('.')[-1]}"]
    command = (record.get("input") or "").lower()
    if any(k in command for k in ("wget", "curl", "tftp")):
        tags.append("payload-fetch")
    if "busybox" in command:
        tags.append("mirai-signature")
    if record.get("url"):
        tags.append("second-stage-url")
    return tags


# --------------------------------------------------------------------------- #
# This project's JSONL
# --------------------------------------------------------------------------- #


def parse_jsonl(path: Path, sensor: str | None) -> Iterator[dict[str, Any]]:
    columns = {column.name for column in Event.__table__.columns}
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            event = {k: v for k, v in record.items() if k in columns}
            event.pop("id", None)
            event.setdefault("event_id", str(uuid.uuid4()))
            ts = _parse_timestamp(event.get("ts"))
            if ts is None:
                continue
            event["ts"] = ts
            if sensor:
                event["sensor"] = sensor
            extra = dict(event.get("extra") or {})
            extra["imported_from"] = path.name
            event["extra"] = extra
            yield event


# --------------------------------------------------------------------------- #
# Linux auth.log
# --------------------------------------------------------------------------- #

AUTH_PATTERNS = [
    (
        "failed_password",
        re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
            r"Failed password for (?:invalid user )?(?P<username>\S+) "
            r"from (?P<src_ip>[\d.a-fA-F:]+) port (?P<src_port>\d+)"
        ),
    ),
    (
        "accepted_password",
        re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
            r"Accepted (?:password|publickey) for (?P<username>\S+) "
            r"from (?P<src_ip>[\d.a-fA-F:]+) port (?P<src_port>\d+)"
        ),
    ),
    (
        "invalid_user",
        re.compile(
            r"^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+"
            r"Invalid user (?P<username>\S+) from (?P<src_ip>[\d.a-fA-F:]+)"
        ),
    ),
]

MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1
    )
}


def parse_auth_log(path: Path, sensor: str, year: int | None = None) -> Iterator[dict[str, Any]]:
    """Parse sshd lines from a syslog-format auth.log.

    Syslog timestamps carry no year. We assume the file's modification-time year
    and roll back one year for entries that would otherwise be in the future —
    the standard workaround for a log that spans New Year.
    """
    default_year = year or dt.datetime.fromtimestamp(path.stat().st_mtime).year
    now = utcnow()
    session_ids: dict[str, str] = {}

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            for kind, pattern in AUTH_PATTERNS:
                match = pattern.match(line)
                if match is None:
                    continue

                fields = match.groupdict()
                try:
                    hour, minute, second = (int(p) for p in fields["time"].split(":"))
                    ts = dt.datetime(
                        default_year,
                        MONTHS[fields["month"]],
                        int(fields["day"]),
                        hour,
                        minute,
                        second,
                        tzinfo=dt.UTC,
                    )
                except (ValueError, KeyError):
                    break
                if ts > now + dt.timedelta(days=1):
                    ts = ts.replace(year=default_year - 1)

                src_ip = fields["src_ip"]
                session_ids.setdefault(src_ip, str(uuid.uuid4()))

                event_type = (
                    EventType.AUTH_SUCCESS
                    if kind == "accepted_password"
                    else EventType.AUTH_ATTEMPT
                )
                severity = Severity.HIGH if kind == "accepted_password" else Severity.MEDIUM

                yield {
                    "event_id": str(uuid.uuid4()),
                    "ts": ts,
                    "sensor": sensor,
                    "session_id": session_ids[src_ip],
                    "service": "ssh",
                    "event_type": event_type.value,
                    "severity": severity.value,
                    "src_ip": src_ip,
                    "src_port": _int_or_none(fields.get("src_port")),
                    "dst_port": 22,
                    "username": fields.get("username"),
                    "tags": [f"authlog:{kind}"],
                    "extra": {"imported_from": path.name, "source": "auth.log"},
                }
                break


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    if isinstance(value, (int, float)):
        return dt.datetime.fromtimestamp(value, tz=dt.UTC)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def create_missing_sessions(db, events: list[dict[str, Any]]) -> int:
    """Create Session rows for every session_id referenced by the events.

    Events carry an FK to sessions, so importing events without their parents
    would fail the constraint on any engine that enforces it.
    """
    from sqlalchemy import select

    existing = {row[0] for row in db.execute(select(Session.session_id))}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        sid = event.get("session_id")
        if sid and sid not in existing:
            grouped.setdefault(sid, []).append(event)

    for session_id, group in grouped.items():
        timestamps = [e["ts"] for e in group]
        first = group[0]
        db.add(
            Session(
                session_id=session_id,
                sensor=first.get("sensor", "imported"),
                service=first.get("service", "ssh"),
                src_ip=first.get("src_ip", "0.0.0.0"),
                src_port=first.get("src_port"),
                dst_port=first.get("dst_port"),
                started_at=min(timestamps),
                ended_at=max(timestamps),
                duration_ms=int((max(timestamps) - min(timestamps)).total_seconds() * 1000),
                event_count=len(group),
                auth_attempts=sum(
                    1 for e in group if e["event_type"] == EventType.AUTH_ATTEMPT.value
                ),
                commands_run=sum(1 for e in group if e["event_type"] == EventType.COMMAND.value),
                country=first.get("country"),
                asn=first.get("asn"),
            )
        )
    db.flush()
    return len(grouped)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import honeypot logs from another source")
    parser.add_argument("path", help="log file to import")
    parser.add_argument("--format", choices=("cowrie", "jsonl", "auth-log"), required=True)
    parser.add_argument("--sensor", help="sensor name to stamp (default: derived from filename)")
    parser.add_argument("--year", type=int, help="auth-log only: year for syslog timestamps")
    parser.add_argument("--limit", type=int, help="stop after N events")
    parser.add_argument("--no-enrich", action="store_true", help="skip geo/ASN/TI enrichment")
    parser.add_argument("--dry-run", action="store_true", help="parse and report, write nothing")
    args = parser.parse_args(argv)

    # Source addresses and org names carry non-ASCII; keep stdout UTF-8 so a
    # legacy Windows console code page does not crash the import at the summary.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    path = Path(args.path)
    if not path.exists():
        print(f"no such file: {path}", file=sys.stderr)
        return 2

    sensor = args.sensor or f"imported-{path.stem[:32]}"

    if args.format == "cowrie":
        stream = parse_cowrie(path, sensor)
    elif args.format == "jsonl":
        stream = parse_jsonl(path, args.sensor)
    else:
        stream = parse_auth_log(path, sensor, year=args.year)

    events: list[dict[str, Any]] = []
    for event in stream:
        events.append(event)
        if args.limit and len(events) >= args.limit:
            break

    if not events:
        print("no importable events found — check --format matches the file", file=sys.stderr)
        return 1

    print(f"parsed {len(events):,} events from {path.name}")
    sources = {e["src_ip"] for e in events}
    span = (min(e["ts"] for e in events), max(e["ts"] for e in events))
    print(f"  {len(sources):,} distinct sources")
    print(f"  {span[0].isoformat()} → {span[1].isoformat()}")

    if args.dry_run:
        print("\n--dry-run: nothing written")
        return 0

    if not args.no_enrich:
        print("enriching...")
        for event in events:
            enrich_event(event)

    init_db()
    print("writing...")
    with session_scope() as db:
        created = create_missing_sessions(db, events)
        for start in range(0, len(events), 1000):
            chunk = events[start : start + 1000]
            db.add_all(
                Event(
                    **{k: v for k, v in e.items() if k in {c.name for c in Event.__table__.columns}}
                )
                for e in chunk
            )
            db.flush()
    print(f"  {created:,} sessions, {len(events):,} events")

    from storage import queries

    print("rebuilding attacker aggregates...")
    with session_scope() as db:
        count = queries.rebuild_attackers(db, src_ips=sources)
    print(f"  {count:,} attacker records")

    return 0


if __name__ == "__main__":
    sys.exit(main())
