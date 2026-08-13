"""Attacker endpoints — the per-source-IP view."""

from __future__ import annotations

import ipaddress
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import (
    AttackerDetail,
    AttackerOut,
    EventOut,
    Message,
    Page,
    ScoreExplanation,
    SessionOut,
    redact_passwords,
)
from storage import queries
from storage.db import get_db

router = APIRouter(prefix="/attackers", tags=["attackers"])

SORT_FIELDS = ("threat_score", "event_count", "last_seen", "first_seen", "auth_attempts")


@router.get("", response_model=Page[AttackerOut], summary="List attackers")
def list_attackers(
    db: OrmSession = Depends(get_db),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    country: Optional[str] = Query(None, min_length=2, max_length=2),
    classification: Optional[str] = Query(
        None, description="botnet-loader | targeted-intrusion | exploit-attempt | ..."
    ),
    min_score: Optional[float] = Query(None, ge=0, le=100),
    sort: str = Query("threat_score"),
) -> Page[AttackerOut]:
    if sort not in SORT_FIELDS:
        raise HTTPException(400, f"cannot sort by {sort!r}; use one of {list(SORT_FIELDS)}")

    rows, total = queries.list_attackers(
        db,
        limit=limit,
        offset=offset,
        country=country,
        classification=classification,
        min_score=min_score,
        sort=sort,
    )
    return Page[AttackerOut](
        items=[AttackerOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/map", summary="Attackers with coordinates, for the world map")
def attacker_map(
    db: OrmSession = Depends(get_db),
    hours: float = Query(24, gt=0, le=24 * 365),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    """Points and per-country totals in one response.

    Bundled deliberately: the map needs both, and two round trips means the
    choropleth and the markers can render from different snapshots.
    """
    rows, _ = queries.list_attackers(db, limit=limit, sort="threat_score")
    points = [
        {
            "src_ip": row.src_ip,
            "lat": row.latitude,
            "lon": row.longitude,
            "country": row.country,
            "country_name": row.country_name,
            "score": row.threat_score,
            "classification": row.classification,
            "events": row.event_count,
            "as_org": row.as_org,
        }
        for row in rows
        if row.latitude is not None and row.longitude is not None
    ]
    return {
        "points": points,
        "countries": queries.top_countries(db, limit=250, since_hours=hours),
        "points_total": len(points),
        "points_without_geo": len(rows) - len(points),
    }


@router.get("/{src_ip}", response_model=AttackerDetail, summary="Attacker profile")
def get_attacker(
    src_ip: str,
    db: OrmSession = Depends(get_db),
    event_limit: int = Query(100, ge=1, le=1000),
    explain: bool = Query(True, description="include the score breakdown"),
) -> AttackerDetail:
    try:
        ipaddress.ip_address(src_ip)
    except ValueError:
        raise HTTPException(400, f"{src_ip!r} is not a valid IP address") from None

    attacker = queries.get_attacker(db, src_ip)
    if attacker is None:
        raise HTTPException(404, f"no attacker {src_ip}")

    sessions = queries.attacker_sessions(db, src_ip, limit=50)
    events, _ = queries.list_events(db, src_ip=src_ip, limit=event_limit, order="desc")

    items = [EventOut.model_validate(event) for event in events]
    import os

    if os.getenv("API_REDACT_PASSWORDS", "").strip().lower() in {"1", "true", "yes", "on"}:
        items = redact_passwords(items)

    detail = AttackerDetail.model_validate(attacker)
    detail.sessions = [SessionOut.model_validate(s) for s in sessions]
    detail.recent_events = items

    if explain:
        from pipeline.detection.scoring import explain as explain_score

        all_events, _ = queries.list_events(db, src_ip=src_ip, limit=5000, order="asc")
        if all_events:
            detail.score_explanation = ScoreExplanation(
                **explain_score(attacker, all_events)
            )

    return detail


@router.post("/rebuild", response_model=Message, summary="Recompute attacker aggregates")
def rebuild(
    db: OrmSession = Depends(get_db),
    src_ip: Optional[str] = Query(None, description="rebuild one IP; omit for all"),
) -> Message:
    """Rebuild the ``attackers`` table from raw events.

    Safe to run at any time — the table is a derived aggregate, never the source
    of truth. Use it after importing historical logs or changing scoring weights.
    """
    updated = queries.rebuild_attackers(db, src_ips=[src_ip] if src_ip else None)
    db.commit()
    return Message(detail=f"rebuilt {updated} attacker record(s)")


__all__ = ["router"]
