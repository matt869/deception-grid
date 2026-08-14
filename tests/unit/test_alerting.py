"""Unit tests for the alert notifier.

No real network: the send method is captured so we assert on *what would be
posted* and to *where*, and on the severity gate and rate cap.
"""

from __future__ import annotations

import pytest

from pipeline.alerting.notify import Notifier, _detect_kind


def _alert(severity="high", rule_id="ssh_bruteforce", **kw):
    base = dict(
        severity=severity,
        rule_id=rule_id,
        rule_name="SSH brute-force",
        title=f"{rule_id}: something from 192.0.2.9",
        src_ip="192.0.2.9",
        description="a description",
        mitre=["T1110.001"],
        evidence={"observed": 42},
    )
    base.update(kw)
    return base


@pytest.fixture
def capture_notifier():
    """A Notifier pointed at a dummy webhook whose sends are captured."""
    n = Notifier(
        webhook_url="https://hooks.slack.com/services/T/B/x", min_severity="high", max_per_run=3
    )
    sent: list[dict] = []
    n._send = lambda payload: sent.append(payload)  # type: ignore[method-assign]
    return n, sent


class TestKindDetection:
    def test_slack(self):
        assert _detect_kind("https://hooks.slack.com/services/x") == "slack"

    def test_discord(self):
        assert _detect_kind("https://discord.com/api/webhooks/1/2") == "discord"

    def test_teams(self):
        assert _detect_kind("https://x.webhook.office.com/y") == "teams"

    def test_generic(self):
        assert _detect_kind("https://example.com/hook") == "generic"


class TestSeverityGate:
    def test_below_threshold_is_dropped(self, capture_notifier):
        n, sent = capture_notifier
        n.notify_many([_alert(severity="medium"), _alert(severity="low")])
        assert sent == []

    def test_at_or_above_threshold_sends(self, capture_notifier):
        n, sent = capture_notifier
        n.notify_many([_alert(severity="high"), _alert(severity="critical")])
        assert len(sent) == 2

    def test_disabled_without_url(self):
        n = Notifier(webhook_url="")
        assert not n.enabled
        assert n.notify_many([_alert(severity="critical")]) == 0


class TestRateCap:
    def test_caps_and_summarises(self, capture_notifier):
        n, sent = capture_notifier  # max_per_run = 3
        n.notify_many([_alert(severity="critical") for _ in range(10)])
        # 3 detailed + 1 overflow summary
        assert len(sent) == 4
        assert "more" in str(sent[-1]).lower()

    def test_most_severe_survive_the_cap(self, capture_notifier):
        n, sent = capture_notifier
        alerts = [_alert(severity="high", rule_id=f"h{i}") for i in range(3)] + [
            _alert(severity="critical", rule_id="crit")
        ]
        n.notify_many(alerts)
        # the critical one must be among the 3 that got through
        bodies = " ".join(str(s) for s in sent[:3])
        assert "crit" in bodies


class TestFormatting:
    def test_slack_payload_shape(self):
        n = Notifier(webhook_url="https://hooks.slack.com/x")
        payload = n._format(_alert(severity="critical"))
        assert "text" in payload and payload["mrkdwn"] is True
        assert "CRITICAL" in payload["text"]

    def test_discord_uses_content(self):
        n = Notifier(webhook_url="https://discord.com/api/webhooks/1/2")
        payload = n._format(_alert())
        assert "content" in payload

    def test_generic_is_structured(self):
        n = Notifier(webhook_url="https://example.com/hook")
        payload = n._format(_alert(severity="high"))
        assert payload["event"] == "honeypot_alert"
        assert payload["src_ip"] == "192.0.2.9"
        assert payload["mitre"] == ["T1110.001"]
