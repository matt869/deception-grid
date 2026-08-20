"""Shared pytest fixtures.

Every test runs against a throwaway SQLite database, created fresh per test
function. The key line is ``reset_state()``: ``storage.db`` caches its engine in
a module global, so without clearing it a test would silently reuse the previous
test's database. Isolation here is not a nicety — a leaked engine turns an
unrelated failure into a debugging afternoon.
"""

from __future__ import annotations

import datetime as dt
import uuid
from pathlib import Path

import pytest

from storage.db import get_engine, init_db, reset_state
from storage.models import Event, EventType, Session, Severity, utcnow


@pytest.fixture
def db_url(tmp_path: Path) -> str:
    return f"sqlite:///{(tmp_path / 'test.db').as_posix()}"


@pytest.fixture
def engine(db_url, monkeypatch):
    """A fresh, initialised database engine bound to a temp file."""
    monkeypatch.setenv("DATABASE_URL", db_url)
    reset_state()
    engine = get_engine(db_url)
    init_db(engine)
    yield engine
    reset_state()


@pytest.fixture
def db(engine):
    """A session on the temp database, rolled back and closed after the test."""
    from sqlalchemy.orm import sessionmaker

    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture
def make_event():
    """Factory for Event rows with sensible defaults.

    Keeps tests declarative: a test states only the fields it cares about, so
    what it is actually asserting on stays legible.
    """
    counter = {"n": 0}

    def _make(**overrides) -> Event:
        counter["n"] += 1
        defaults = dict(
            event_id=str(uuid.uuid4()),
            ts=utcnow(),
            sensor="test",
            service="ssh",
            event_type=EventType.AUTH_ATTEMPT.value,
            severity=Severity.MEDIUM.value,
            src_ip="192.0.2.10",
            src_port=40000 + counter["n"],
            dst_port=22,
            tags=[],
            threat_tags=[],
            extra={},
        )
        defaults.update(overrides)
        return Event(**defaults)

    return _make


@pytest.fixture
def make_session_row():
    def _make(**overrides) -> Session:
        defaults = dict(
            session_id=str(uuid.uuid4()),
            sensor="test",
            service="ssh",
            src_ip="192.0.2.10",
            src_port=40000,
            dst_port=22,
            started_at=utcnow(),
        )
        defaults.update(overrides)
        return Session(**defaults)

    return _make


@pytest.fixture
def burst(make_event):
    """Build a time-clustered burst of events for one source.

    ``spacing_seconds`` between consecutive events, anchored ``ago_minutes`` in
    the past — the shape detection rules are written against.
    """

    def _burst(
        count: int,
        *,
        src_ip: str = "192.0.2.50",
        spacing_seconds: float = 1.0,
        ago_minutes: float = 1.0,
        **event_kwargs,
    ) -> list[Event]:
        base = utcnow() - dt.timedelta(minutes=ago_minutes)
        return [
            make_event(
                src_ip=src_ip,
                ts=base + dt.timedelta(seconds=i * spacing_seconds),
                **event_kwargs,
            )
            for i in range(count)
        ]

    return _burst


# --------------------------------------------------------------------------- #
# Protocol harness
# --------------------------------------------------------------------------- #
#
# Drives a service's ``handle_session`` against a scripted byte stream with no
# sockets and no database. ``asyncio.StreamReader`` is the real class fed by
# hand, so the parsers under test see exactly the framing a peer would send —
# short reads, missing terminators and all.


class RecordingLogger:
    """EventLogger stand-in that keeps everything in memory."""

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.sessions: list[dict] = []

    def emit(self, event: dict) -> bool:
        self.events.append(event)
        return True

    def emit_session(self, row: dict) -> bool:
        self.sessions.append(row)
        return True

    # -- assertion helpers -------------------------------------------------

    def tags(self) -> set[str]:
        return {tag for event in self.events for tag in event.get("tags") or []}

    def of_type(self, event_type) -> list[dict]:
        wanted = getattr(event_type, "value", event_type)
        return [e for e in self.events if e["event_type"] == wanted]

    def tagged(self, tag: str) -> list[dict]:
        return [e for e in self.events if tag in (e.get("tags") or [])]


class FakeWriter:
    """StreamWriter stand-in that accumulates what the service sent."""

    def __init__(self) -> None:
        self.chunks: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.chunks.append(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        pass

    def get_extra_info(self, name, default=None):
        return ("192.0.2.77", 51234) if name == "peername" else default

    @property
    def text(self) -> str:
        return b"".join(self.chunks).decode("utf-8", "replace")


@pytest.fixture
def protocol_harness():
    """Run one scripted conversation against a service class.

    Returns ``(writer, logger, session)`` so a test can assert on the bytes
    sent back, the events recorded, and the end state of the session.
    """
    import asyncio

    from honeypot.config import Settings
    from honeypot.session import HoneypotSession, SessionRegistry

    def _run(service_class, script: bytes, **settings_overrides):
        settings = Settings(**settings_overrides)
        logger = RecordingLogger()
        registry = SessionRegistry(settings)
        service = service_class(settings, logger, registry, port=0)

        writer = FakeWriter()
        session = HoneypotSession(
            service=service.name,
            src_ip="192.0.2.77",
            src_port=51234,
            dst_port=0,
            logger=logger,
            settings=settings,
        )

        async def _drive():
            # StreamReader binds to the running loop at construction, so it has
            # to be built in here rather than by the caller.
            reader = asyncio.StreamReader()
            reader.feed_data(script)
            reader.feed_eof()
            await service.handle_session(session, reader, writer)

        asyncio.run(_drive())
        return writer, logger, session

    return _run
