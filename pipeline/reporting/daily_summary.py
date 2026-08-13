"""Daily summary report.

Produces the "what happened yesterday" digest — the artifact somebody actually
reads, as opposed to the dashboard they mean to check and don't.

Renders to Markdown or plain text. Deliberately no HTML email sending: what to
do with the report (commit it, post it to Slack, pipe it to `mail`) is a
deployment decision, and baking in an SMTP client would mean holding credentials
this project has no business holding.

    python -m pipeline.reporting.daily_summary --days 1 --format markdown
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
from typing import Any

from sqlalchemy import select

from storage import queries
from storage.db import session_scope
from storage.models import Alert, Attacker, Event, ensure_utc, utcnow

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def build_summary(db, hours: float = 24, top_n: int = 10) -> dict[str, Any]:
    """Gather every figure the report needs in one pass over the window."""
    stats = queries.summary_stats(db, since_hours=hours)
    window_start = utcnow() - dt.timedelta(hours=hours)

    alerts = list(
        db.execute(
            select(Alert).where(Alert.last_seen >= window_start).order_by(Alert.last_seen.desc())
        ).scalars()
    )
    by_severity: dict[str, int] = {name: 0 for name in SEVERITY_ORDER}
    for alert in alerts:
        by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1

    top_attackers = list(
        db.execute(
            select(Attacker)
            .where(Attacker.last_seen >= window_start)
            .order_by(Attacker.threat_score.desc())
            .limit(top_n)
        ).scalars()
    )

    # Sources seen in this window but never before it — the new arrivals.
    new_attackers = [a for a in top_attackers if ensure_utc(a.first_seen) >= window_start]

    payload_urls = _collect_payload_urls(db, window_start)

    return {
        "generated_at": utcnow(),
        "window_hours": hours,
        "window_start": window_start,
        "stats": stats,
        "services": queries.service_breakdown(db, since_hours=hours),
        "top_countries": queries.top_countries(db, limit=top_n, since_hours=hours),
        "top_asns": queries.top_asns(db, limit=top_n, since_hours=hours),
        "top_usernames": queries.top_usernames(db, limit=top_n, since_hours=hours),
        "top_passwords": queries.top_passwords(db, limit=top_n, since_hours=hours),
        "top_paths": queries.top_paths(db, limit=top_n, since_hours=hours),
        "top_commands": queries.top_commands(db, limit=top_n, since_hours=hours),
        "credential_pairs": queries.credential_pairs(db, limit=top_n, since_hours=hours),
        "alerts_by_severity": by_severity,
        "alerts_by_rule": queries.alert_counts_by_rule(db, since_hours=hours),
        "notable_alerts": [_alert_row(a) for a in alerts if a.severity in ("critical", "high")][
            :top_n
        ],
        "top_attackers": [_attacker_row(a) for a in top_attackers],
        "new_attackers": [_attacker_row(a) for a in new_attackers],
        "payload_urls": payload_urls,
    }


def _collect_payload_urls(db, window_start: dt.datetime) -> list[str]:
    """Second-stage URLs the attackers asked us to fetch (we never did)."""
    rows = db.execute(
        select(Event.command)
        .where(Event.ts >= window_start)
        .where(Event.command.is_not(None))
        .where(
            Event.command.ilike("%http://%")
            | Event.command.ilike("%https://%")
            | Event.command.ilike("%tftp%")
        )
    ).scalars()

    import re

    pattern = re.compile(r"(?:https?|ftp|tftp)://[^\s;'\"|&)]+")
    found: list[str] = []
    for command in rows:
        for url in pattern.findall(command or ""):
            if url not in found:
                found.append(url)
    return found[:50]


def _alert_row(alert: Alert) -> dict[str, Any]:
    return {
        "rule_id": alert.rule_id,
        "rule_name": alert.rule_name,
        "severity": alert.severity,
        "src_ip": alert.src_ip,
        "title": alert.title,
        "hit_count": alert.hit_count,
        "last_seen": ensure_utc(alert.last_seen),
        "mitre": alert.mitre or [],
    }


def _attacker_row(attacker: Attacker) -> dict[str, Any]:
    return {
        "src_ip": attacker.src_ip,
        "score": attacker.threat_score,
        "classification": attacker.classification,
        "country": attacker.country,
        "as_org": attacker.as_org,
        "events": attacker.event_count,
        "sessions": attacker.session_count,
        "services": attacker.services or [],
        "tags": attacker.tags or [],
        "first_seen": ensure_utc(attacker.first_seen),
        "last_seen": ensure_utc(attacker.last_seen),
    }


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def render_markdown(summary: dict[str, Any]) -> str:
    stats = summary["stats"]
    start = summary["window_start"].strftime("%Y-%m-%d %H:%M")
    end = summary["generated_at"].strftime("%Y-%m-%d %H:%M")

    out: list[str] = [
        "# Honeypot daily summary",
        "",
        f"**Window:** {start} → {end} UTC ({summary['window_hours']:g}h)",
        "",
        "## At a glance",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Events | {stats['total_events']:,} |",
        f"| Unique sources | {stats['unique_attackers']:,} |",
        f"| Countries | {stats['unique_countries']:,} |",
        f"| Sessions | {stats['sessions']:,} |",
        f"| Auth attempts | {stats['auth_attempts']:,} |",
        f"| Distinct credential pairs | {stats['unique_credential_pairs']:,} |",
        f"| Commands executed | {stats['commands_run']:,} |",
        f"| Open alerts | {stats['open_alerts']:,} |",
        "",
    ]

    counts = summary["alerts_by_severity"]
    if any(counts.values()):
        out += ["## Alerts by severity", ""]
        out += [f"- **{name}**: {counts[name]}" for name in SEVERITY_ORDER if counts.get(name)]
        out += [""]

    if summary["notable_alerts"]:
        out += [
            "## Notable alerts",
            "",
            "| Severity | Rule | Source | Hits |",
            "| --- | --- | --- | ---: |",
        ]
        for alert in summary["notable_alerts"]:
            out.append(
                f"| {alert['severity']} | {alert['rule_name']} | "
                f"`{alert['src_ip'] or '—'}` | {alert['hit_count']} |"
            )
        out.append("")

    if summary["top_attackers"]:
        out += [
            "## Top sources by threat score",
            "",
            "| Score | Source | Class | Country | Network | Events |",
            "| ---: | --- | --- | --- | --- | ---: |",
        ]
        for row in summary["top_attackers"]:
            out.append(
                f"| {row['score']:.0f} | `{row['src_ip']}` | {row['classification'] or '—'} | "
                f"{row['country'] or '—'} | {(row['as_org'] or '—')[:32]} | {row['events']:,} |"
            )
        out.append("")

    out += _table_section("Most-tried usernames", summary["top_usernames"], "Username")
    out += _table_section("Most-tried passwords", summary["top_passwords"], "Password")
    out += _table_section("Most-requested paths", summary["top_paths"], "Path")

    if summary["credential_pairs"]:
        out += [
            "## Top credential pairs",
            "",
            "| Username | Password | Count |",
            "| --- | --- | ---: |",
        ]
        for pair in summary["credential_pairs"]:
            out.append(f"| `{pair['username']}` | `{pair['password'] or ''}` | {pair['count']:,} |")
        out.append("")

    if summary["top_countries"]:
        out += [
            "## Source countries",
            "",
            "| Country | Events | Sources |",
            "| --- | ---: | ---: |",
        ]
        for row in summary["top_countries"]:
            name = row["country_name"] or row["country"]
            out.append(f"| {name} ({row['country']}) | {row['events']:,} | {row['attackers']:,} |")
        out.append("")

    if summary["payload_urls"]:
        out += [
            "## Second-stage payload URLs observed",
            "",
            "> Recorded from commands run inside the emulated shell. "
            "The sensor never requested any of these.",
            "",
        ]
        out += [f"- `{url}`" for url in summary["payload_urls"]]
        out.append("")

    if summary["new_attackers"]:
        out += [f"## First seen in this window ({len(summary['new_attackers'])})", ""]
        out += [
            f"- `{row['src_ip']}` — {row['classification']} "
            f"({row['country'] or '??'}, score {row['score']:.0f})"
            for row in summary["new_attackers"]
        ]
        out.append("")

    return "\n".join(out)


def _table_section(title: str, rows: list[dict[str, Any]], label: str) -> list[str]:
    if not rows:
        return []
    out = [f"## {title}", "", f"| {label} | Count |", "| --- | ---: |"]
    for row in rows:
        value = str(row["value"])[:80].replace("|", "\\|")
        out.append(f"| `{value}` | {row['count']:,} |")
    out.append("")
    return out


def render_text(summary: dict[str, Any]) -> str:
    """Plain-text rendering for terminals and `mail`."""
    import re

    markdown = render_markdown(summary)
    text = re.sub(r"^#+\s*", "", markdown, flags=re.M)
    text = text.replace("|", " ").replace("**", "").replace("`", "")
    return re.sub(r"^\s*-+\s+-+.*$", "", text, flags=re.M)


def _force_utf8_stdout() -> None:
    """Make stdout UTF-8 regardless of the platform's default console encoding.

    Windows consoles default to a legacy code page (cp1252) that cannot encode
    the arrows and box characters in the report, so an un-redirected run crashes
    with UnicodeEncodeError. Reconfiguring is the portable fix; ``errors`` guards
    the rare terminal that still can't render a glyph.
    """
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-reconfigurable stream
        pass


def main(argv: list[str] | None = None) -> int:
    _force_utf8_stdout()
    parser = argparse.ArgumentParser(description="Generate the honeypot daily summary")
    parser.add_argument("--days", type=float, default=1.0, help="window in days (default 1)")
    parser.add_argument("--hours", type=float, help="window in hours; overrides --days")
    parser.add_argument("--top", type=int, default=10, help="rows per top-N table")
    parser.add_argument("--format", choices=("markdown", "text", "json"), default="markdown")
    parser.add_argument("--out", help="write to this file instead of stdout")
    args = parser.parse_args(argv)

    hours = args.hours if args.hours is not None else args.days * 24

    with session_scope() as db:
        summary = build_summary(db, hours=hours, top_n=args.top)

    if args.format == "json":
        import json

        rendered = json.dumps(summary, default=str, indent=2)
    elif args.format == "text":
        rendered = render_text(summary)
    else:
        rendered = render_markdown(summary)

    if args.out:
        from pathlib import Path

        path = Path(args.out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
        print(f"wrote {path} ({len(rendered):,} bytes)", file=sys.stderr)
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    sys.exit(main())
