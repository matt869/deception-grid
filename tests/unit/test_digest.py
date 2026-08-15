"""Unit tests for the daily digest.

No network: payloads are built and inspected directly. The assertions that
matter are the ones about *safety and honesty of the rendering* — defanged
payload URLs, per-platform bold markers, truncation that admits it truncated,
and a JSON-serialisable generic payload.
"""

from __future__ import annotations

import datetime as dt
import json

import pytest

from pipeline.reporting.digest import (
    QUIET_COLOR,
    SEVERITY_COLORS,
    _defang,
    _jsonable,
    _lines,
    build_fields,
    build_payload,
    digest_color,
)


def _summary(**overrides):
    """A summary shaped like build_summary's output, with everything empty."""
    now = dt.datetime(2026, 8, 15, 12, 0, tzinfo=dt.UTC)
    base = {
        "generated_at": now,
        "window_hours": 24,
        "window_start": now - dt.timedelta(hours=24),
        "stats": {
            "total_events": 100,
            "unique_attackers": 7,
            "unique_countries": 3,
            "sessions": 12,
            "auth_attempts": 44,
            "unique_credential_pairs": 30,
            "commands_run": 5,
            "open_alerts": 2,
            "critical_alerts": 1,
        },
        "services": [{"service": "ssh", "events": 90, "attackers": 5}],
        "top_countries": [],
        "top_asns": [],
        "top_usernames": [],
        "top_passwords": [],
        "top_paths": [],
        "top_commands": [],
        "credential_pairs": [],
        "alerts_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "alerts_by_rule": [],
        "notable_alerts": [],
        "top_attackers": [],
        "new_attackers": [],
        "payload_urls": [],
    }
    base.update(overrides)
    return base


class TestDefang:
    def test_url_is_not_clickable(self):
        assert _defang("http://evil.com/x.sh") == "hxxp://evil[.]com/x[.]sh"

    def test_https_too(self):
        assert _defang("https://a.b/c") == "hxxps://a[.]b/c"

    def test_only_the_scheme_is_rewritten(self):
        # A path segment containing "http" must not be mangled twice.
        assert _defang("http://x.io/http/y").startswith("hxxp://")
        assert _defang("http://x.io/http/y").count("hxxp") == 1

    def test_payload_urls_reach_the_embed_defanged(self):
        summary = _summary(payload_urls=["http://198.51.100.77/bins/mirai.arm7"])
        field = next(f for f in build_fields(summary, 5) if "Second-stage" in f["name"])
        assert "hxxp://198[.]51[.]100[.]77" in field["value"]
        assert "http://198.51.100.77" not in field["value"]


class TestLines:
    def test_empty_renders_a_dash(self):
        assert _lines([], str, 5) == "—"

    def test_truncation_is_declared(self):
        out = _lines(list(range(10)), str, 3)
        assert out.splitlines()[-1] == "_+7 more_"

    def test_no_tail_when_everything_fits(self):
        assert "more" not in _lines([1, 2], str, 5)

    def test_value_stays_within_discord_field_limit(self):
        rows = [{"value": "x" * 100, "count": 1} for _ in range(50)]
        out = _lines(rows, lambda r: f"`{r['value']}` x{r['count']}", 50)
        assert len(out) <= 1024


class TestColor:
    def test_worst_severity_wins(self):
        summary = _summary(
            alerts_by_severity={"critical": 1, "high": 9, "medium": 0, "low": 0, "info": 0}
        )
        assert digest_color(summary) == SEVERITY_COLORS["critical"]

    def test_high_when_no_critical(self):
        summary = _summary(
            alerts_by_severity={"critical": 0, "high": 3, "medium": 5, "low": 0, "info": 0}
        )
        assert digest_color(summary) == SEVERITY_COLORS["high"]

    def test_quiet_day_with_traffic_is_green(self):
        assert digest_color(_summary()) == QUIET_COLOR

    def test_no_events_is_not_green(self):
        """A silent sensor is usually a broken sensor — don't paint it healthy."""
        stats = dict(_summary()["stats"], total_events=0)
        assert digest_color(_summary(stats=stats)) == SEVERITY_COLORS["info"]


class TestFields:
    def test_empty_sections_are_omitted(self):
        names = [f["name"] for f in build_fields(_summary(), 5)]
        assert "Volume" in names
        assert not any("Usernames" in n for n in names)
        assert not any("Second-stage" in n for n in names)

    def test_populated_sections_appear(self):
        summary = _summary(
            top_usernames=[{"value": "root", "count": 12}],
            top_attackers=[
                {
                    "src_ip": "192.0.2.9",
                    "score": 71.4,
                    "classification": "botnet-loader",
                    "country": "NL",
                    "events": 40,
                    "as_org": "Example",
                    "sessions": 2,
                    "services": ["ssh"],
                    "tags": [],
                    "first_seen": dt.datetime(2026, 8, 15, tzinfo=dt.UTC),
                    "last_seen": dt.datetime(2026, 8, 15, tzinfo=dt.UTC),
                }
            ],
        )
        fields = {f["name"]: f["value"] for f in build_fields(summary, 5)}
        assert "`root` ×12" in fields["Usernames"]
        assert "192.0.2.9" in fields["Top sources"]
        assert "71" in fields["Top sources"]

    def test_never_exceeds_discord_field_cap(self):
        summary = _summary(
            top_usernames=[{"value": f"u{i}", "count": i} for i in range(100)],
            top_passwords=[{"value": f"p{i}", "count": i} for i in range(100)],
            top_paths=[{"value": f"/p{i}", "count": i} for i in range(100)],
            payload_urls=[f"http://x{i}.com/a" for i in range(100)],
        )
        fields = build_fields(summary, 5)
        assert len(fields) <= 25
        assert all(len(f["value"]) <= 1024 for f in fields)


class TestPayloadShapes:
    def test_discord_uses_embeds(self):
        payload = build_payload(_summary(), "discord", sensor="hp", top_n=5)
        assert len(payload["embeds"]) == 1
        assert "hp" in payload["embeds"][0]["title"]

    def test_slack_downgrades_bold_to_mrkdwn(self):
        payload = build_payload(_summary(), "slack", sensor="hp", top_n=5)
        assert payload["mrkdwn"] is True
        assert "**" not in payload["text"]
        assert "*hp*" in payload["text"]

    def test_teams_keeps_standard_markdown(self):
        payload = build_payload(_summary(), "teams", sensor="hp", top_n=5)
        assert "**hp**" in payload["text"]

    def test_generic_is_structured_and_serialisable(self):
        summary = _summary(
            top_attackers=[
                {
                    "src_ip": "192.0.2.9",
                    "score": 10.0,
                    "classification": "recon-scanner",
                    "country": "NL",
                    "events": 3,
                    "as_org": "X",
                    "sessions": 1,
                    "services": ["ssh"],
                    "tags": [],
                    "first_seen": dt.datetime(2026, 8, 14, tzinfo=dt.UTC),
                    "last_seen": dt.datetime(2026, 8, 15, tzinfo=dt.UTC),
                }
            ],
            payload_urls=["http://evil.com/x"],
        )
        payload = build_payload(summary, "generic", sensor="hp", top_n=5)
        assert payload["event"] == "honeypot_daily_digest"
        # The whole point: this goes straight into json.dumps in post_webhook.
        encoded = json.loads(json.dumps(payload))
        assert encoded["top_attackers"][0]["last_seen"] == "2026-08-15T00:00:00+00:00"
        assert encoded["payload_urls"] == ["hxxp://evil[.]com/x"]

    @pytest.mark.parametrize("kind", ["discord", "slack", "teams", "generic"])
    def test_every_kind_is_json_serialisable(self, kind):
        payload = build_payload(_summary(), kind, sensor="hp", top_n=5)
        json.dumps(payload)  # must not raise

    def test_empty_window_says_so(self):
        stats = dict(_summary()["stats"], total_events=0, unique_attackers=0)
        payload = build_payload(_summary(stats=stats), "discord", sensor="hp", top_n=5)
        assert "No events recorded" in payload["embeds"][0]["description"]


class TestJsonable:
    def test_nested_datetimes_are_converted(self):
        value = _jsonable({"a": [{"b": dt.datetime(2026, 1, 1, tzinfo=dt.UTC)}]})
        assert value["a"][0]["b"] == "2026-01-01T00:00:00+00:00"

    def test_other_types_pass_through(self):
        assert _jsonable({"n": 1, "s": "x", "f": 1.5, "none": None}) == {
            "n": 1,
            "s": "x",
            "f": 1.5,
            "none": None,
        }
