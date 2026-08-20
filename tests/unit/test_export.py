"""Unit tests for the export formats.

The indicator exporters are what other people's infrastructure consumes, so the
assertions here are about *contract*, not formatting: a blocklist a firewall
reads line-by-line must not grow an unlabelled comment, a STIX id must stay
stable across runs so a TIP updates an indicator instead of duplicating it, and
the MISP ``to_ids`` flag must stay off for weak signals — that flag is what
turns an observation into somebody's dropped packet.
"""

from __future__ import annotations

import datetime as dt
import json

from pipeline.reporting import export
from storage.models import Attacker, utcnow


def make_attacker(**overrides) -> Attacker:
    now = utcnow()
    defaults = dict(
        src_ip="203.0.113.9",
        first_seen=now - dt.timedelta(hours=6),
        last_seen=now,
        event_count=42,
        session_count=3,
        services=["ssh", "http"],
        threat_score=80.0,
        classification="brute-forcer",
        tags=["scanner:masscan"],
    )
    defaults.update(overrides)
    return Attacker(**defaults)


# --------------------------------------------------------------------------- #
# Blocklist
# --------------------------------------------------------------------------- #


class TestBlocklist:
    def test_bare_list_is_only_addresses(self):
        attackers = [make_attacker(src_ip="203.0.113.1"), make_attacker(src_ip="203.0.113.2")]
        lines = export.export_blocklist(attackers, comment=False).splitlines()
        assert lines == ["203.0.113.1", "203.0.113.2"]

    def test_commented_list_marks_every_non_address_line(self):
        # A firewall that ignores '#' lines must still see exactly the IPs.
        text = export.export_blocklist([])  # header only
        assert all(line.startswith("#") for line in text.splitlines())

        text = export.export_blocklist([make_attacker(src_ip="203.0.113.7")])
        addresses = [line for line in text.splitlines() if not line.startswith("#")]
        assert addresses == ["203.0.113.7"]

    def test_output_ends_with_newline(self):
        # Concatenating two exports must not glue an IP onto the previous line.
        assert export.export_blocklist([make_attacker()], comment=False).endswith("\n")


# --------------------------------------------------------------------------- #
# STIX 2.1
# --------------------------------------------------------------------------- #


class TestStix:
    def test_bundle_shape(self):
        bundle = json.loads(export.export_stix([make_attacker()]))
        assert bundle["type"] == "bundle"
        assert bundle["id"].startswith("bundle--")
        types = [obj["type"] for obj in bundle["objects"]]
        assert types == ["identity", "indicator"]

    def test_indicator_pattern_and_provenance(self):
        bundle = json.loads(export.export_stix([make_attacker(src_ip="203.0.113.4")]))
        identity, indicator = bundle["objects"]
        assert indicator["pattern"] == "[ipv4-addr:value = '203.0.113.4']"
        assert indicator["pattern_type"] == "stix"
        assert indicator["created_by_ref"] == identity["id"]
        assert indicator["indicator_types"] == ["malicious-activity"]

    def test_indicator_id_is_stable_for_the_same_source(self):
        # Re-exporting must update the TIP's indicator, not create a second one.
        first = json.loads(export.export_stix([make_attacker(src_ip="203.0.113.5")]))
        second = json.loads(export.export_stix([make_attacker(src_ip="203.0.113.5")]))
        assert first["objects"][1]["id"] == second["objects"][1]["id"]
        assert first["id"] != second["id"]  # ...but each bundle is its own

    def test_confidence_is_clamped_to_the_stix_range(self):
        bundle = json.loads(export.export_stix([make_attacker(threat_score=130.0)]))
        assert bundle["objects"][1]["confidence"] == 100

    def test_timestamps_use_the_z_suffix(self):
        bundle = json.loads(export.export_stix([make_attacker()]))
        indicator = bundle["objects"][1]
        assert indicator["valid_from"].endswith("Z")
        assert "+00:00" not in indicator["modified"]

    def test_missing_tags_and_classification_do_not_break_labels(self):
        bundle = json.loads(
            export.export_stix([make_attacker(tags=None, classification=None, services=None)])
        )
        assert bundle["objects"][1]["labels"] == ["unclassified"]


# --------------------------------------------------------------------------- #
# MISP
# --------------------------------------------------------------------------- #


class TestMisp:
    def test_one_ip_src_attribute_per_source(self):
        event = json.loads(export.export_misp([make_attacker(src_ip="203.0.113.8")]))["Event"]
        assert len(event["Attribute"]) == 1
        assert event["Attribute"][0]["type"] == "ip-src"
        assert event["Attribute"][0]["value"] == "203.0.113.8"

    def test_to_ids_only_for_strong_signals(self):
        # to_ids is what becomes somebody's IDS rule. 70 is the floor, inclusive.
        attackers = [
            make_attacker(src_ip="203.0.113.1", threat_score=69.9),
            make_attacker(src_ip="203.0.113.2", threat_score=70.0),
            make_attacker(src_ip="203.0.113.3", threat_score=95.0),
        ]
        attributes = json.loads(export.export_misp(attackers))["Event"]["Attribute"]
        assert [a["to_ids"] for a in attributes] == [False, True, True]

    def test_distribution_defaults_to_organisation_only(self):
        # Widening this is a deliberate act, never an export default.
        event = json.loads(export.export_misp([make_attacker()]))["Event"]
        assert event["distribution"] == "0"

    def test_timestamp_is_a_unix_string(self):
        attribute = json.loads(export.export_misp([make_attacker()]))["Event"]["Attribute"][0]
        assert int(attribute["timestamp"]) > 0


# --------------------------------------------------------------------------- #
# Event exports (database-backed)
# --------------------------------------------------------------------------- #


class TestEventExports:
    def test_jsonl_one_record_per_event_without_the_row_id(self, db, make_event):
        db.add_all([make_event(src_ip="203.0.113.1"), make_event(src_ip="203.0.113.2")])
        db.commit()

        lines = export.export_events_jsonl(db).splitlines()
        assert len(lines) == 2
        records = [json.loads(line) for line in lines]
        assert {r["src_ip"] for r in records} == {"203.0.113.1", "203.0.113.2"}
        # The autoincrement primary key is local to this database; re-importing
        # elsewhere must not carry it along.
        assert all("id" not in record for record in records)

    def test_jsonl_timestamps_round_trip_as_aware_utc(self, db, make_event):
        db.add(make_event())
        db.commit()
        record = json.loads(export.export_events_jsonl(db).splitlines()[0])
        parsed = dt.datetime.fromisoformat(record["ts"])
        assert parsed.tzinfo is not None
        assert parsed.utcoffset() == dt.timedelta(0)

    def test_jsonl_on_empty_database_is_empty_not_a_blank_line(self, db):
        assert export.export_events_jsonl(db) == ""

    def test_csv_has_a_header_and_one_row_per_event(self, db, make_event):
        db.add_all([make_event(), make_event()])
        db.commit()
        lines = export.export_events_csv(db).strip().splitlines()
        assert lines[0].startswith("event_id,ts,sensor")
        assert len(lines) == 3

    def test_since_hours_excludes_older_events(self, db, make_event):
        db.add_all(
            [
                make_event(src_ip="203.0.113.1", ts=utcnow() - dt.timedelta(hours=48)),
                make_event(src_ip="203.0.113.2", ts=utcnow() - dt.timedelta(minutes=5)),
            ]
        )
        db.commit()
        lines = export.export_events_jsonl(db, since_hours=1).splitlines()
        assert [json.loads(line)["src_ip"] for line in lines] == ["203.0.113.2"]


# --------------------------------------------------------------------------- #
# Indicator selection
# --------------------------------------------------------------------------- #


class TestSelectIndicators:
    def test_score_floor_is_applied(self, db):
        db.add_all(
            [
                make_attacker(src_ip="203.0.113.1", threat_score=20.0),
                make_attacker(src_ip="203.0.113.2", threat_score=75.0),
            ]
        )
        db.commit()
        selected = export.select_indicators(db, min_score=50.0)
        assert [a.src_ip for a in selected] == ["203.0.113.2"]

    def test_results_are_ordered_by_score_descending(self, db):
        db.add_all(
            [
                make_attacker(src_ip="203.0.113.1", threat_score=60.0),
                make_attacker(src_ip="203.0.113.2", threat_score=90.0),
                make_attacker(src_ip="203.0.113.3", threat_score=75.0),
            ]
        )
        db.commit()
        scores = [a.threat_score for a in export.select_indicators(db, min_score=50.0)]
        assert scores == sorted(scores, reverse=True)

    def test_stale_sources_drop_out_of_the_window(self, db):
        db.add_all(
            [
                make_attacker(
                    src_ip="203.0.113.1",
                    threat_score=90.0,
                    last_seen=utcnow() - dt.timedelta(days=30),
                ),
                make_attacker(src_ip="203.0.113.2", threat_score=90.0),
            ]
        )
        db.commit()
        selected = export.select_indicators(db, min_score=50.0, since_hours=24)
        assert [a.src_ip for a in selected] == ["203.0.113.2"]
