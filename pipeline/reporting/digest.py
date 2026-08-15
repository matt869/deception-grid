"""Daily digest delivery.

Takes the same figures as :mod:`pipeline.reporting.daily_summary` and pushes
them to a chat webhook once a day, so the honeypot reports in rather than
waiting to be checked. Real-time alerting (:mod:`pipeline.alerting.notify`)
answers "something just happened"; this answers "what happened yesterday" —
including the quiet answer, which is itself worth seeing, because a sensor that
reports zero events for a day is usually a sensor that has fallen over.

    python -m pipeline.reporting.digest --hours 24            # send
    python -m pipeline.reporting.digest --dry-run             # print the payload

Configuration (environment variables):

    DIGEST_WEBHOOK_URL    webhook to POST to (falls back to ALERT_WEBHOOK_URL)
    DIGEST_WEBHOOK_KIND   slack | discord | teams | generic  (default: auto-detect)
    DIGEST_HOURS          reporting window in hours          (default: 24)
    DIGEST_TOP_N          rows per top-N section             (default: 5)
    DASHBOARD_URL         link included in the footer        (optional)
    SENSOR_NAME           label in the title                 (default: honeypot)

**On second-stage URLs:** the digest defangs every captured payload URL
(``http`` → ``hxxp``, ``.`` → ``[.]``) before posting. Chat clients unfurl links
and some people click them; posting live malware-distribution URLs into a
channel as clickable text is a way to turn an observation into an incident.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from typing import Any

from pipeline.alerting.notify import _detect_kind, post_webhook
from pipeline.reporting.daily_summary import build_summary
from storage.db import session_scope

# Discord's documented ceilings. Exceeding any of them is a 400, not a truncation.
MAX_FIELD_VALUE = 1024
MAX_FIELDS = 25
MAX_DESCRIPTION = 4096

# Embed accent, worst-first: the strip of colour is the only part read at a glance.
SEVERITY_COLORS = {
    "critical": 0xD4212F,
    "high": 0xEB6834,
    "medium": 0xEDA100,
    "low": 0x2A78D6,
    "info": 0x6B7280,
}
QUIET_COLOR = 0x1BAF7A


def _defang(url: str) -> str:
    """Render a URL inert for a chat client: hxxp://evil[.]com/x."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def _jsonable(value: Any) -> Any:
    """Recursively convert datetimes to ISO strings.

    The summary rows carry real ``datetime`` objects (the Markdown report
    formats them itself). The chat renderings never touch those fields, but the
    ``generic`` payload forwards rows wholesale, and ``json.dumps`` refuses a
    datetime — so the conversion happens here rather than by loosening the
    webhook poster's encoder for every caller.
    """
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    return value


def _clip(text: str, limit: int = MAX_FIELD_VALUE) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _lines(rows: list[Any], fmt, limit: int) -> str:
    """Render up to ``limit`` rows, flagging anything it left out.

    The "+N more" tail matters: a section header that says 30 while the body
    lists 5 reads as a bug, and silently dropping the rest reads as a smaller
    day than it was.
    """
    if not rows:
        return "—"
    shown = [fmt(row) for row in rows[:limit]]
    if len(rows) > limit:
        shown.append(f"_+{len(rows) - limit} more_")
    return _clip("\n".join(shown))


def digest_color(summary: dict[str, Any]) -> int:
    counts = summary["alerts_by_severity"]
    for name in ("critical", "high", "medium", "low"):
        if counts.get(name):
            return SEVERITY_COLORS[name]
    return QUIET_COLOR if summary["stats"]["total_events"] else SEVERITY_COLORS["info"]


def build_fields(summary: dict[str, Any], top_n: int) -> list[dict[str, Any]]:
    """The digest body, as Discord embed fields.

    Sections that would be empty are dropped rather than printed as "none" —
    a digest that is mostly em dashes trains people to stop reading it.
    """
    stats = summary["stats"]
    fields: list[dict[str, Any]] = [
        {
            "name": "Volume",
            "value": (
                f"**{stats['total_events']:,}** events · "
                f"**{stats['unique_attackers']:,}** sources · "
                f"{stats['unique_countries']:,} countries · "
                f"{stats['sessions']:,} sessions"
            ),
            "inline": False,
        },
        {
            "name": "Credentials",
            "value": (
                f"{stats['auth_attempts']:,} attempts · "
                f"{stats['unique_credential_pairs']:,} distinct pairs · "
                f"{stats['commands_run']:,} commands run"
            ),
            "inline": False,
        },
    ]

    counts = summary["alerts_by_severity"]
    if any(counts.values()):
        parts = [f"{name}: **{counts[name]}**" for name in SEVERITY_COLORS if counts.get(name)]
        fields.append({"name": "Alerts raised", "value": " · ".join(parts), "inline": False})

    if summary["notable_alerts"]:
        fields.append(
            {
                "name": f"Notable alerts ({len(summary['notable_alerts'])})",
                "value": _lines(
                    summary["notable_alerts"],
                    lambda a: f"`{a['src_ip'] or 'n/a'}` {a['rule_name']} ×{a['hit_count']}",
                    top_n,
                ),
                "inline": False,
            }
        )

    if summary["top_attackers"]:
        fields.append(
            {
                "name": "Top sources",
                "value": _lines(
                    summary["top_attackers"],
                    lambda a: (
                        f"`{a['src_ip']}` **{a['score']:.0f}** {a['classification'] or '—'} "
                        f"({a['country'] or '??'}, {a['events']:,} events)"
                    ),
                    top_n,
                ),
                "inline": False,
            }
        )

    if summary["top_usernames"]:
        fields.append(
            {
                "name": "Usernames",
                "value": _lines(
                    summary["top_usernames"], lambda r: f"`{r['value']}` ×{r['count']:,}", top_n
                ),
                "inline": True,
            }
        )
    if summary["top_passwords"]:
        fields.append(
            {
                "name": "Passwords",
                "value": _lines(
                    summary["top_passwords"], lambda r: f"`{r['value']}` ×{r['count']:,}", top_n
                ),
                "inline": True,
            }
        )

    if summary["services"]:
        fields.append(
            {
                "name": "Services hit",
                "value": _clip(
                    " · ".join(f"{s['service']} {s['events']:,}" for s in summary["services"])
                ),
                "inline": False,
            }
        )

    if summary["top_paths"]:
        fields.append(
            {
                "name": "Requested paths",
                "value": _lines(
                    summary["top_paths"], lambda r: f"`{r['value'][:60]}` ×{r['count']:,}", top_n
                ),
                "inline": False,
            }
        )

    if summary["payload_urls"]:
        fields.append(
            {
                "name": f"Second-stage URLs ({len(summary['payload_urls'])}) — defanged",
                "value": _lines(summary["payload_urls"], lambda u: f"`{_defang(u)}`", top_n),
                "inline": False,
            }
        )

    if summary["new_attackers"]:
        fields.append(
            {
                "name": f"First seen in this window ({len(summary['new_attackers'])})",
                "value": _lines(
                    summary["new_attackers"],
                    lambda a: (
                        f"`{a['src_ip']}` {a['classification'] or '—'} ({a['country'] or '??'})"
                    ),
                    top_n,
                ),
                "inline": False,
            }
        )

    return fields[:MAX_FIELDS]


def render_discord(
    summary: dict[str, Any], sensor: str, top_n: int, dashboard_url: str = ""
) -> dict:
    stats = summary["stats"]
    start = summary["window_start"].strftime("%Y-%m-%d %H:%M")
    end = summary["generated_at"].strftime("%Y-%m-%d %H:%M")

    if stats["total_events"]:
        headline = (
            f"**{stats['total_events']:,}** events from "
            f"**{stats['unique_attackers']:,}** sources in the last "
            f"{summary['window_hours']:g}h."
        )
    else:
        headline = (
            "No events recorded in this window. If that is unexpected, check that "
            "the sensor is running and the bait ports are reachable."
        )

    embed = {
        "title": f"🍯 {sensor} — daily digest",
        "description": _clip(f"{headline}\n`{start}` → `{end}` UTC", MAX_DESCRIPTION),
        "color": digest_color(summary),
        "fields": build_fields(summary, top_n),
        "footer": {"text": dashboard_url or "honeypot-dashboard"},
        "timestamp": summary["generated_at"].isoformat(),
    }
    return {"embeds": [embed]}


def render_text(summary: dict[str, Any], sensor: str, top_n: int) -> str:
    """Flat rendering for Slack / Teams / anything without embeds.

    Emits standard ``**bold**`` markdown; :func:`build_payload` downgrades it to
    Slack's single-asterisk mrkdwn, which would otherwise render the literal
    asterisks.
    """
    stats = summary["stats"]
    lines = [
        f"**{sensor}** — honeypot daily digest ({summary['window_hours']:g}h)",
        f"{stats['total_events']:,} events · {stats['unique_attackers']:,} sources · "
        f"{stats['unique_countries']:,} countries · {stats['sessions']:,} sessions",
        f"{stats['auth_attempts']:,} auth attempts · "
        f"{stats['unique_credential_pairs']:,} distinct credential pairs · "
        f"{stats['commands_run']:,} commands",
    ]
    for field in build_fields(summary, top_n):
        lines.append(f"\n**{field['name']}**\n{field['value']}")
    return "\n".join(lines)


def build_payload(
    summary: dict[str, Any],
    kind: str,
    *,
    sensor: str,
    top_n: int,
    dashboard_url: str = "",
) -> dict[str, Any]:
    """Shape the digest for one webhook flavour."""
    if kind == "discord":
        return render_discord(summary, sensor, top_n, dashboard_url)
    if kind == "slack":
        # Slack mrkdwn is single-asterisk bold; **x** would render literally.
        return {"text": render_text(summary, sensor, top_n).replace("**", "*"), "mrkdwn": True}
    if kind == "teams":
        return {"text": render_text(summary, sensor, top_n)}
    return _jsonable(
        {
            "sensor": sensor,
            "event": "honeypot_daily_digest",
            "window_hours": summary["window_hours"],
            "generated_at": summary["generated_at"],
            "stats": summary["stats"],
            "alerts_by_severity": summary["alerts_by_severity"],
            "notable_alerts": summary["notable_alerts"][:top_n],
            "top_attackers": summary["top_attackers"][:top_n],
            "top_usernames": summary["top_usernames"][:top_n],
            "top_passwords": summary["top_passwords"][:top_n],
            "payload_urls": [_defang(u) for u in summary["payload_urls"]],
        }
    )


def send_digest(
    *,
    hours: float | None = None,
    top_n: int | None = None,
    webhook_url: str | None = None,
    kind: str | None = None,
    dry_run: bool = False,
    skip_if_empty: bool = False,
) -> dict[str, Any]:
    """Build and deliver the digest. Returns a small result dict.

    Never raises on delivery failure — this runs from cron, where the useful
    behaviour is a logged failure rather than a stack trace in a mail spool.
    """
    url = webhook_url or os.getenv("DIGEST_WEBHOOK_URL") or os.getenv("ALERT_WEBHOOK_URL", "")
    url = url.strip()
    hours = hours if hours is not None else float(os.getenv("DIGEST_HOURS", "24"))
    top_n = top_n if top_n is not None else int(os.getenv("DIGEST_TOP_N", "5"))
    sensor = os.getenv("SENSOR_NAME", "honeypot")
    dashboard_url = os.getenv("DASHBOARD_URL", "").strip()

    if not url and not dry_run:
        return {"enabled": False, "sent": False, "reason": "no DIGEST_WEBHOOK_URL set"}

    resolved = (kind or os.getenv("DIGEST_WEBHOOK_KIND", "") or "").strip().lower()
    if not resolved:
        resolved = _detect_kind(url) if url else "discord"

    with session_scope() as db:
        summary = build_summary(db, hours=hours, top_n=max(top_n, 10))

    if skip_if_empty and not summary["stats"]["total_events"]:
        return {"enabled": True, "sent": False, "reason": "no events in window (--skip-if-empty)"}

    payload = build_payload(
        summary, resolved, sensor=sensor, top_n=top_n, dashboard_url=dashboard_url
    )

    if dry_run:
        return {"enabled": bool(url), "sent": False, "kind": resolved, "payload": payload}

    ok = post_webhook(url, payload)
    return {
        "enabled": True,
        "sent": ok,
        "kind": resolved,
        "events": summary["stats"]["total_events"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send the honeypot daily digest to a webhook")
    parser.add_argument("--hours", type=float, help="window in hours (default 24)")
    parser.add_argument("--top", type=int, help="rows per section (default 5)")
    parser.add_argument("--webhook", help="override DIGEST_WEBHOOK_URL")
    parser.add_argument("--kind", choices=("discord", "slack", "teams", "generic"))
    parser.add_argument(
        "--dry-run", action="store_true", help="print the payload instead of posting it"
    )
    parser.add_argument(
        "--skip-if-empty", action="store_true", help="post nothing when the window had no events"
    )
    args = parser.parse_args(argv)

    logging_level = os.getenv("LOG_LEVEL", "INFO").upper()
    import logging

    logging.basicConfig(level=logging_level, format="%(levelname)-7s %(name)-20s %(message)s")

    result = send_digest(
        hours=args.hours,
        top_n=args.top,
        webhook_url=args.webhook,
        kind=args.kind,
        dry_run=args.dry_run,
        skip_if_empty=args.skip_if_empty,
    )

    if args.dry_run:
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):  # pragma: no cover
            pass
        print(json.dumps(result.get("payload", {}), indent=2, ensure_ascii=False))
        return 0

    if not result["enabled"]:
        print(f"digest not sent: {result['reason']}", file=sys.stderr)
        return 2
    if not result["sent"]:
        print(
            f"digest not sent: {result.get('reason', 'webhook delivery failed')}", file=sys.stderr
        )
        return 0 if result.get("reason") else 1

    print(f"digest sent to {result['kind']} ({result['events']:,} events)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["send_digest", "build_payload", "build_fields", "render_discord", "render_text"]
