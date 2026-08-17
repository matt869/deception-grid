"""Unit tests for ATT&CK coverage.

The assertion that matters is the one the module exists to protect: a rule that
has never fired must never be reported as coverage. Everything else here guards
the bookkeeping around that distinction.
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest

from pipeline.detection.coverage import (
    TACTIC_ORDER,
    TECHNIQUES,
    coverage_report,
    rule_techniques,
    unmapped_techniques,
)
from storage.models import Alert, utcnow


@pytest.fixture
def make_alert(db):
    def _make(mitre: list[str], *, severity="high", hit_count=1, ago_hours=1.0) -> Alert:
        alert = Alert(
            alert_id=str(uuid.uuid4()),
            rule_id="test_rule",
            rule_name="Test rule",
            severity=severity,
            src_ip="192.0.2.1",
            title="t",
            mitre=mitre,
            hit_count=hit_count,
            first_seen=utcnow() - dt.timedelta(hours=ago_hours),
            last_seen=utcnow() - dt.timedelta(hours=ago_hours),
            dedupe_key=str(uuid.uuid4()),
        )
        db.add(alert)
        db.flush()
        return alert

    return _make


class TestTechniqueTable:
    def test_every_rule_technique_is_mapped(self):
        """A rule referencing an unmapped technique should be caught here, not in prod."""
        assert unmapped_techniques() == []

    def test_rules_claim_techniques(self):
        claims = rule_techniques()
        assert claims, "rule set should reference at least one technique"
        assert all(rules for rules in claims.values())

    def test_all_mapped_tactics_are_known(self):
        for _name, tactic in TECHNIQUES.values():
            assert tactic in TACTIC_ORDER


class TestCoverageStatus:
    def test_rule_only_when_nothing_has_fired(self, db):
        """The core claim: rules without alerts are not coverage."""
        report = coverage_report(db)
        assert report["totals"]["techniques_observed"] == 0
        assert report["totals"]["techniques_rule_only"] > 0
        assert all(t["status"] == "rule-only" for t in report["techniques"])
        assert report["totals"]["observed_share"] == 0.0

    def test_technique_becomes_observed_once_an_alert_exists(self, db, make_alert):
        make_alert(["T1110.001"])
        report = coverage_report(db)
        row = next(t for t in report["techniques"] if t["technique"] == "T1110.001")
        assert row["status"] == "observed"
        assert row["alerts"] == 1
        assert report["totals"]["techniques_observed"] == 1

    def test_hit_counts_accumulate_across_alerts(self, db, make_alert):
        make_alert(["T1110.001"], hit_count=5)
        make_alert(["T1110.001"], hit_count=7)
        row = next(t for t in coverage_report(db)["techniques"] if t["technique"] == "T1110.001")
        assert row["alerts"] == 2
        assert row["hits"] == 12

    def test_worst_severity_wins(self, db, make_alert):
        make_alert(["T1110.001"], severity="low")
        make_alert(["T1110.001"], severity="critical")
        make_alert(["T1110.001"], severity="medium")
        row = next(t for t in coverage_report(db)["techniques"] if t["technique"] == "T1110.001")
        assert row["worst_severity"] == "critical"

    def test_alert_with_no_matching_rule_is_orphaned(self, db, make_alert):
        make_alert(["T9999"])
        row = next(t for t in coverage_report(db)["techniques"] if t["technique"] == "T9999")
        assert row["status"] == "orphaned"
        assert row["rule_count"] == 0

    def test_multi_technique_alert_credits_each(self, db, make_alert):
        make_alert(["T1110.001", "T1078.001"])
        report = coverage_report(db)
        observed = {t["technique"] for t in report["techniques"] if t["status"] == "observed"}
        assert {"T1110.001", "T1078.001"} <= observed


class TestWindowing:
    def test_window_excludes_older_alerts(self, db, make_alert):
        make_alert(["T1110.001"], ago_hours=100)
        assert coverage_report(db, since_hours=24)["totals"]["techniques_observed"] == 0
        # ...but the all-history default still sees it.
        assert coverage_report(db)["totals"]["techniques_observed"] == 1


class TestReportShape:
    def test_tactics_are_in_kill_chain_order(self, db):
        report = coverage_report(db)
        indexes = [TACTIC_ORDER.index(t) for t in report["tactics"] if t in TACTIC_ORDER]
        assert indexes == sorted(indexes)

    def test_every_technique_lands_in_its_tactic_bucket(self, db):
        report = coverage_report(db)
        for tactic, rows in report["by_tactic"].items():
            assert all(r["tactic"] == tactic for r in rows)
        total = sum(len(v) for v in report["by_tactic"].values())
        assert total == len(report["techniques"])

    def test_json_serialisable(self, db, make_alert):
        import json

        make_alert(["T1110.001"])
        json.dumps(coverage_report(db))  # must not raise
