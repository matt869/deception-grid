"""Push notifications for newly-raised alerts.

Turns the sensor from something you check into something that tells you. When
detection creates a *new* alert at or above a severity threshold, a short
message is POSTed to a Slack / Discord / Microsoft Teams / generic webhook.

Design choices:

* **Only new alerts notify.** Detection re-runs every few minutes and is
  idempotent; notifying on every run would be a firehose. Because alerts are
  deduplicated (one row per condition), "new" means "a condition we had not
  seen before" — exactly what a human wants paged about.
* **Stdlib only.** ``urllib.request`` instead of ``requests`` so the notifier
  adds zero dependencies and runs in the existing API image.
* **Best-effort, never fatal.** A webhook being down must never break the
  detection pipeline. Every send is wrapped; failures are logged and counted.
* **Rate-capped.** A burst (say a scan that trips ten rules at once) sends at
  most ``ALERT_MAX_PER_RUN`` messages plus one "+N more" summary, so a noisy
  minute can't flood the channel or the webhook's own rate limit.

Configuration (environment variables):

    ALERT_WEBHOOK_URL     the webhook to POST to (unset = notifications disabled)
    ALERT_WEBHOOK_KIND    slack | discord | teams | generic   (default: auto-detect)
    ALERT_MIN_SEVERITY    info|low|medium|high|critical        (default: high)
    ALERT_MAX_PER_RUN     max messages per detection run       (default: 8)
    SENSOR_NAME           label included in the message        (default: honeypot)
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from collections.abc import Iterable
from typing import Any

from storage.models import Severity

log = logging.getLogger("pipeline.alerting")

_SEV_EMOJI = {
    "critical": "\U0001f6a8",  # rotating light
    "high": "⚠️",  # warning
    "medium": "\U0001f7e1",  # yellow circle
    "low": "\U0001f535",  # blue circle
    "info": "ℹ️",  # info
}


def _detect_kind(url: str) -> str:
    lowered = url.lower()
    if "hooks.slack.com" in lowered:
        return "slack"
    if "discord.com/api/webhooks" in lowered or "discordapp.com" in lowered:
        return "discord"
    if "webhook.office.com" in lowered or "office365.com" in lowered:
        return "teams"
    return "generic"


def post_webhook(url: str, payload: dict[str, Any], timeout: float = 8.0) -> bool:
    """POST one JSON payload to a webhook. Returns True on success.

    Shared by the alert notifier and the daily digest. Never raises: a webhook
    being down must not break the pipeline that called it.
    """
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "honeypot-notifier/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            if resp.status >= 300:
                log.warning("webhook returned %s", resp.status)
                return False
            return True
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("webhook failed: %s", exc)
        return False


class Notifier:
    """Formats and delivers alert notifications to a configured webhook."""

    def __init__(
        self,
        webhook_url: str | None = None,
        kind: str | None = None,
        min_severity: str | None = None,
        max_per_run: int | None = None,
        sensor_name: str | None = None,
        timeout: float = 8.0,
    ) -> None:
        self.webhook_url = (
            webhook_url if webhook_url is not None else os.getenv("ALERT_WEBHOOK_URL", "").strip()
        )
        self.kind = (kind or os.getenv("ALERT_WEBHOOK_KIND", "") or "").strip().lower()
        if self.webhook_url and not self.kind:
            self.kind = _detect_kind(self.webhook_url)
        self.min_rank = Severity(
            (min_severity or os.getenv("ALERT_MIN_SEVERITY", "high") or "high").strip()
        ).rank
        self.max_per_run = int(
            max_per_run if max_per_run is not None else os.getenv("ALERT_MAX_PER_RUN", "8")
        )
        self.sensor_name = sensor_name or os.getenv("SENSOR_NAME", "honeypot")
        self.timeout = timeout

        self.sent = 0
        self.failed = 0

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    # ------------------------------------------------------------------ #

    def notify_many(self, alerts: Iterable[dict[str, Any]]) -> int:
        """Notify for every alert at/above the threshold. Returns count sent."""
        if not self.enabled:
            return 0

        eligible = [a for a in alerts if self._passes(a)]
        # Most severe first, so if we hit the cap the worst ones still get through.
        eligible.sort(key=lambda a: Severity(a.get("severity", "info")).rank, reverse=True)

        to_send = eligible[: self.max_per_run]
        overflow = len(eligible) - len(to_send)

        for alert in to_send:
            self._send(self._format(alert))

        if overflow > 0:
            self._send(self._format_summary(overflow))

        return len(to_send)

    def _passes(self, alert: dict[str, Any]) -> bool:
        try:
            return Severity(alert.get("severity", "info")).rank >= self.min_rank
        except ValueError:
            return False

    # ------------------------------------------------------------------ #
    # Formatting per platform
    # ------------------------------------------------------------------ #

    def _headline(self, alert: dict[str, Any]) -> str:
        sev = alert.get("severity", "info")
        emoji = _SEV_EMOJI.get(sev, "")
        src = alert.get("src_ip") or "n/a"
        mitre = ", ".join(alert.get("mitre") or [])
        title = alert.get("title") or alert.get("rule_name") or alert.get("rule_id", "alert")
        tail = f" · {mitre}" if mitre else ""
        return f"{emoji} [{sev.upper()}] {title} — source {src}{tail}"

    def _format(self, alert: dict[str, Any]) -> dict[str, Any]:
        text = f"*{self.sensor_name}* honeypot alert\n{self._headline(alert)}"
        desc = (alert.get("description") or "").strip()
        if desc:
            text += f"\n{desc}"

        if self.kind == "slack":
            return {"text": text, "mrkdwn": True}
        if self.kind == "discord":
            # Discord: <=2000 chars, **bold** markdown.
            return {"content": text.replace("*", "**")[:1900]}
        if self.kind == "teams":
            return {"text": text.replace("*", "**")}
        # generic: structured payload for your own consumer
        return {
            "sensor": self.sensor_name,
            "event": "honeypot_alert",
            "severity": alert.get("severity"),
            "rule_id": alert.get("rule_id"),
            "title": alert.get("title"),
            "src_ip": alert.get("src_ip"),
            "mitre": alert.get("mitre") or [],
            "description": alert.get("description"),
            "evidence": alert.get("evidence"),
        }

    def _format_summary(self, overflow: int) -> dict[str, Any]:
        text = f"*{self.sensor_name}* honeypot: +{overflow} more alert(s) this run (rate-capped)"
        if self.kind == "slack":
            return {"text": text, "mrkdwn": True}
        if self.kind in ("discord", "teams"):
            return (
                {"content": text.replace("*", "**")}
                if self.kind == "discord"
                else {"text": text.replace("*", "**")}
            )
        return {
            "sensor": self.sensor_name,
            "event": "honeypot_alert_overflow",
            "additional": overflow,
        }

    # ------------------------------------------------------------------ #

    def _send(self, payload: dict[str, Any]) -> None:
        if post_webhook(self.webhook_url, payload, timeout=self.timeout):
            self.sent += 1
        else:
            self.failed += 1


def notify_new_alerts(alerts: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Convenience entry point used by the detection pipeline.

    Builds a Notifier from the environment and sends. Returns a small stats
    dict; a disabled or failing notifier is not an error.
    """
    notifier = Notifier()
    if not notifier.enabled:
        return {"enabled": 0, "sent": 0, "failed": 0}
    sent = notifier.notify_many(alerts)
    return {"enabled": 1, "sent": sent, "failed": notifier.failed}


__all__ = ["Notifier", "notify_new_alerts", "post_webhook"]
