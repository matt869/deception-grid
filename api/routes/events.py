"""Event and session endpoints — the raw observation feed."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import EventOut, Page, SessionDetail, redact_passwords
from storage import queries
from storage.db import get_db
from storage.models import EventType, Service, Severity

router = APIRouter(prefix="/events", tags=["events"])


def _should_redact() -> bool:
    return os.getenv("API_REDACT_PASSWORDS", "").strip().lower() in {"1", "true", "yes", "on"}


@router.get("", response_model=Page[EventOut], summary="List events")
def list_events(
    db: OrmSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    service: str | None = Query(None, description="ssh | telnet | ftp | http"),
    event_type: str | None = Query(None),
    src_ip: str | None = Query(None),
    country: str | None = Query(None, min_length=2, max_length=2),
    username: str | None = Query(None),
    session_id: str | None = Query(None),
    min_severity: str | None = Query(None, description="info | low | medium | high | critical"),
    search: str | None = Query(None, description="substring match on command, path, username, UA"),
    since_hours: float | None = Query(None, gt=0, le=24 * 365),
    order: str = Query("desc", pattern="^(asc|desc)$"),
) -> Page[EventOut]:
    # Validate enum-ish parameters here rather than letting them silently match
    # nothing — a typo in `service` should be a 400, not an empty list.
    if service and service not in {s.value for s in Service}:
        raise HTTPException(400, f"unknown service {service!r}")
    if event_type and event_type not in {e.value for e in EventType}:
        raise HTTPException(400, f"unknown event_type {event_type!r}")
    if min_severity and min_severity not in {s.value for s in Severity}:
        raise HTTPException(400, f"unknown severity {min_severity!r}")

    rows, total = queries.list_events(
        db,
        limit=limit,
        offset=offset,
        service=service,
        event_type=event_type,
        src_ip=src_ip,
        country=country,
        username=username,
        session_id=session_id,
        min_severity=min_severity,
        search=search,
        since_hours=since_hours,
        order=order,
    )

    items = [EventOut.model_validate(row) for row in rows]
    if _should_redact():
        items = redact_passwords(items)

    return Page[EventOut](items=items, total=total, limit=limit, offset=offset)


@router.get("/live", response_model=list[EventOut], summary="Newest events")
def live_events(
    db: OrmSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    after_id: str | None = Query(
        None, description="Return only events newer than this event_id (cursor for polling)"
    ),
    min_severity: str | None = Query(None),
) -> list[EventOut]:
    """Feed endpoint for the live view.

    ``after_id`` makes polling incremental: the dashboard passes the newest
    event_id it already has and gets only what arrived since. Without it, a
    2-second poll re-transfers the same 50 rows forever.
    """
    rows, _ = queries.list_events(db, limit=limit, min_severity=min_severity, order="desc")

    if after_id:
        cutoff = next((i for i, row in enumerate(rows) if row.event_id == after_id), None)
        rows = rows[:cutoff] if cutoff is not None else rows

    items = [EventOut.model_validate(row) for row in rows]
    if _should_redact():
        items = redact_passwords(items)
    return items


@router.get("/{event_id}", response_model=EventOut, summary="Get one event")
def get_event(event_id: str, db: OrmSession = Depends(get_db)) -> EventOut:
    from sqlalchemy import select

    from storage.models import Event

    row = db.execute(select(Event).where(Event.event_id == event_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, f"no event {event_id}")

    item = EventOut.model_validate(row)
    if _should_redact():
        item = redact_passwords([item])[0]
    return item


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #

sessions_router = APIRouter(prefix="/sessions", tags=["sessions"])


@sessions_router.get("/{session_id}", response_model=SessionDetail, summary="Session transcript")
def get_session(session_id: str, db: OrmSession = Depends(get_db)) -> SessionDetail:
    """Full transcript of one connection, in order.

    This is the highest-value read in the API: for a session that reached the
    shell, it is a replay of exactly what the attacker did.
    """
    session = queries.get_session_with_events(db, session_id)
    if session is None:
        raise HTTPException(404, f"no session {session_id}")

    events, _ = queries.list_events(db, session_id=session_id, limit=1000, order="asc")
    items = [EventOut.model_validate(event) for event in events]
    if _should_redact():
        items = redact_passwords(items)

    detail = SessionDetail.model_validate(session)
    detail.events = items
    return detail


__all__ = ["router", "sessions_router"]
