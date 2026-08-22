"""API-level tests for the campaigns endpoint.

These drive the real app, so they also cover the schema boundary: a field the
clusterer computes but ``CampaignOut`` never declares would silently vanish
from the response, and only a test that reads the JSON notices.
"""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from storage.db import get_engine, init_db, reset_state, session_scope
from storage.models import Event, EventType, Severity, utcnow


def event(src_ip: str, **kwargs) -> Event:
    defaults = dict(
        event_id=str(uuid.uuid4()),
        ts=utcnow(),
        sensor="t",
        service="ssh",
        event_type=EventType.AUTH_ATTEMPT.value,
        severity=Severity.MEDIUM.value,
        src_ip=src_ip,
        dst_port=22,
        tags=[],
        threat_tags=[],
        extra={},
    )
    defaults.update(kwargs)
    return Event(**defaults)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Two credential-sharing sources, plus one unrelated scanner."""
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{(tmp_path / 'c.db').as_posix()}")
    reset_state()
    init_db(get_engine())

    with session_scope() as db:
        for ip in ("45.33.32.1", "45.33.32.2"):
            for _ in range(3):
                db.add(event(ip, username="root", password="hunter2", path="/shell.php"))
        db.add(event("93.184.216.9", username="nobody", password="zzz", path="/unrelated"))

    from storage import queries

    with session_scope() as db:
        queries.rebuild_attackers(db)

    from api.main import app

    with TestClient(app) as c:
        yield c
    reset_state()


class TestCampaignsEndpoint:
    def test_groups_the_credential_sharers(self, client):
        body = client.get("/api/campaigns").json()
        assert len(body) == 1
        assert body[0]["members"] == ["45.33.32.1", "45.33.32.2"]

    def test_excludes_the_unrelated_source(self, client):
        body = client.get("/api/campaigns").json()
        assert "93.184.216.9" not in body[0]["members"]

    def test_reports_the_evidence(self, client):
        campaign = client.get("/api/campaigns").json()[0]
        assert campaign["shared_credentials"] == ["root:hunter2"]
        assert campaign["shared_paths"] == ["/shell.php"]

    def test_reports_size_events_and_cohesion(self, client):
        campaign = client.get("/api/campaigns").json()[0]
        assert campaign["size"] == 2
        assert campaign["event_count"] == 6
        assert 0.0 <= campaign["cohesion"] <= 1.0

    def test_an_unreachable_threshold_returns_an_empty_list(self, client):
        assert client.get("/api/campaigns?threshold=1.0&min_size=3").json() == []

    def test_threshold_is_bounded(self, client):
        assert client.get("/api/campaigns?threshold=1.5").status_code == 422
        assert client.get("/api/campaigns?threshold=-0.1").status_code == 422

    def test_min_size_filters_small_groups(self, client):
        assert client.get("/api/campaigns?min_size=5").json() == []

    def test_limit_is_bounded(self, client):
        assert client.get("/api/campaigns?limit=999999").status_code == 422

    def test_response_is_json_serialisable_end_to_end(self, client):
        response = client.get("/api/campaigns")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
