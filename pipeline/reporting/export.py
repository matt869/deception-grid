"""Export observations to formats other tools consume.

Supported targets:

* ``csv``    — events, flattened, for spreadsheets and pandas
* ``jsonl``  — one event per line, for log shippers and re-import
* ``stix``   — STIX 2.1 bundle of indicators, for a TIP or ISAC submission
* ``misp``   — MISP event JSON
* ``blocklist`` — plain IP list, for a firewall or WAF

    python -m pipeline.reporting.export --format stix --min-score 60 --out iocs.json

A note on the indicator formats: only sources that *did something*, above a
score floor you set, are exported. A honeypot sees a great deal of harmless
background scanning, and publishing every IP that ever touched port 22 produces
a blocklist that mostly blocks researchers and NAT gateways. The default floor
of 50 is a starting point, not a recommendation — validate before you publish
anything that will cause somebody else to drop traffic.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import io
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

from sqlalchemy import select

from storage.db import session_scope
from storage.models import Alert, Attacker, Event, ensure_utc, utcnow

EVENT_CSV_COLUMNS = [
    "event_id", "ts", "sensor", "service", "event_type", "severity",
    "src_ip", "src_port", "dst_port", "username", "password", "command",
    "http_method", "path", "user_agent", "status_code",
    "country", "country_name", "city", "asn", "as_org",
    "threat_score", "session_id",
]


# --------------------------------------------------------------------------- #
# Event exports
# --------------------------------------------------------------------------- #


def export_events_csv(db, since_hours: Optional[float] = None, limit: int = 100_000) -> str:
    stmt = select(Event).order_by(Event.ts)
    if since_hours is not None:
        stmt = stmt.where(Event.ts >= utcnow() - dt.timedelta(hours=since_hours))
    stmt = stmt.limit(limit)

    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EVENT_CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for event in db.execute(stmt).scalars():
        row = {name: getattr(event, name, None) for name in EVENT_CSV_COLUMNS}
        row["ts"] = ensure_utc(event.ts).isoformat()
        writer.writerow(row)
    return buffer.getvalue()


def export_events_jsonl(db, since_hours: Optional[float] = None, limit: int = 100_000) -> str:
    stmt = select(Event).order_by(Event.ts)
    if since_hours is not None:
        stmt = stmt.where(Event.ts >= utcnow() - dt.timedelta(hours=since_hours))
    stmt = stmt.limit(limit)

    lines: list[str] = []
    for event in db.execute(stmt).scalars():
        record = {
            column.name: getattr(event, column.name) for column in Event.__table__.columns
        }
        record["ts"] = ensure_utc(event.ts).isoformat()
        record.pop("id", None)
        lines.append(json.dumps(record, default=str))
    return "\n".join(lines) + ("\n" if lines else "")


# --------------------------------------------------------------------------- #
# Indicator exports
# --------------------------------------------------------------------------- #


def select_indicators(
    db, min_score: float = 50.0, since_hours: Optional[float] = 24 * 7, limit: int = 5000
) -> list[Attacker]:
    """Attackers meeting the export bar. See the module docstring."""
    stmt = (
        select(Attacker)
        .where(Attacker.threat_score >= min_score)
        .order_by(Attacker.threat_score.desc())
        .limit(limit)
    )
    if since_hours is not None:
        stmt = stmt.where(Attacker.last_seen >= utcnow() - dt.timedelta(hours=since_hours))
    return list(db.execute(stmt).scalars())


def export_blocklist(attackers: Sequence[Attacker], comment: bool = True) -> str:
    """Plain IP list with optional provenance comments."""
    lines: list[str] = []
    if comment:
        lines += [
            f"# Honeypot-derived blocklist generated {utcnow().isoformat()}",
            f"# {len(attackers)} sources; each was observed interacting with a honeypot sensor.",
            "# Review before deploying: shared NAT and cloud egress addresses appear here too.",
            "#",
        ]
    for attacker in attackers:
        if comment:
            lines.append(
                f"# score={attacker.threat_score:.0f} class={attacker.classification} "
                f"events={attacker.event_count} last={ensure_utc(attacker.last_seen).date()}"
            )
        lines.append(attacker.src_ip)
    return "\n".join(lines) + "\n"


def export_stix(attackers: Sequence[Attacker], sensor: str = "honeypot") -> str:
    """STIX 2.1 bundle of ``indicator`` objects."""
    now = utcnow().isoformat().replace("+00:00", "Z")
    identity_id = f"identity--{uuid.uuid5(uuid.NAMESPACE_DNS, sensor)}"

    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": f"honeypot-dashboard sensor: {sensor}",
            "identity_class": "system",
            "description": "Deception sensor. Indicators are sources observed attacking it.",
        }
    ]

    for attacker in attackers:
        first = ensure_utc(attacker.first_seen).isoformat().replace("+00:00", "Z")
        last = ensure_utc(attacker.last_seen).isoformat().replace("+00:00", "Z")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, attacker.src_ip)}",
                "created_by_ref": identity_id,
                "created": first,
                "modified": last,
                "valid_from": first,
                "name": f"Honeypot source {attacker.src_ip}",
                "description": (
                    f"Observed {attacker.event_count} events across "
                    f"{attacker.session_count} sessions on {', '.join(attacker.services or [])}. "
                    f"Classification: {attacker.classification}. "
                    f"Confidence score {attacker.threat_score:.0f}/100."
                ),
                "indicator_types": ["malicious-activity"],
                "pattern": f"[ipv4-addr:value = '{attacker.src_ip}']",
                "pattern_type": "stix",
                "confidence": int(min(attacker.threat_score, 100)),
                "labels": list(attacker.tags or []) + [attacker.classification or "unclassified"],
            }
        )

    return json.dumps(
        {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}, indent=2
    )


def export_misp(attackers: Sequence[Attacker], sensor: str = "honeypot") -> str:
    """MISP event JSON with one ``ip-src`` attribute per source."""
    today = utcnow().date().isoformat()
    attributes = [
        {
            "type": "ip-src",
            "category": "Network activity",
            "value": attacker.src_ip,
            "to_ids": attacker.threat_score >= 70,  # only strong signals become IDS rules
            "comment": (
                f"{attacker.classification}; score {attacker.threat_score:.0f}; "
                f"{attacker.event_count} events; services: {','.join(attacker.services or [])}"
            ),
            "timestamp": str(int(ensure_utc(attacker.last_seen).timestamp())),
        }
        for attacker in attackers
    ]

    return json.dumps(
        {
            "Event": {
                "info": f"Honeypot observations from sensor {sensor} — {today}",
                "date": today,
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "0",  # organisation-only by default; widen deliberately
                "Attribute": attributes,
            }
        },
        indent=2,
    )


def export_alerts_csv(db, since_hours: Optional[float] = None) -> str:
    stmt = select(Alert).order_by(Alert.last_seen.desc())
    if since_hours is not None:
        stmt = stmt.where(Alert.last_seen >= utcnow() - dt.timedelta(hours=since_hours))

    columns = ["alert_id", "rule_id", "rule_name", "severity", "src_ip", "service",
               "title", "hit_count", "status", "first_seen", "last_seen"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for alert in db.execute(stmt).scalars():
        row = {name: getattr(alert, name, None) for name in columns}
        row["first_seen"] = ensure_utc(alert.first_seen).isoformat()
        row["last_seen"] = ensure_utc(alert.last_seen).isoformat()
        writer.writerow(row)
    return buffer.getvalue()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Export honeypot data")
    parser.add_argument(
        "--format",
        choices=("csv", "jsonl", "stix", "misp", "blocklist", "alerts-csv"),
        required=True,
    )
    parser.add_argument("--out", help="output file (default: stdout)")
    parser.add_argument("--hours", type=float, help="only include the last N hours")
    parser.add_argument(
        "--min-score", type=float, default=50.0,
        help="score floor for indicator formats (default 50)",
    )
    parser.add_argument("--sensor", default="honeypot", help="sensor name for STIX/MISP")
    parser.add_argument("--limit", type=int, default=100_000)
    parser.add_argument(
        "--no-comments", action="store_true", help="blocklist: omit provenance comments"
    )
    args = parser.parse_args(argv)

    with session_scope() as db:
        if args.format == "csv":
            output = export_events_csv(db, since_hours=args.hours, limit=args.limit)
        elif args.format == "jsonl":
            output = export_events_jsonl(db, since_hours=args.hours, limit=args.limit)
        elif args.format == "alerts-csv":
            output = export_alerts_csv(db, since_hours=args.hours)
        else:
            attackers = select_indicators(
                db, min_score=args.min_score, since_hours=args.hours, limit=args.limit
            )
            if not attackers:
                print(
                    f"no sources scored >= {args.min_score}; nothing to export",
                    file=sys.stderr,
                )
            if args.format == "stix":
                output = export_stix(attackers, sensor=args.sensor)
            elif args.format == "misp":
                output = export_misp(attackers, sensor=args.sensor)
            else:
                output = export_blocklist(attackers, comment=not args.no_comments)

    if args.out:
        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(output, encoding="utf-8")
        print(f"wrote {path} ({len(output):,} bytes)", file=sys.stderr)
    else:
        sys.stdout.write(output)

    return 0


if __name__ == "__main__":
    sys.exit(main())
