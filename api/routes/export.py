"""IOC / data export endpoints.

Turns captures into deployable defense: pull a blocklist, a STIX bundle, a MISP
event, or raw events/alerts as CSV — over the same tunnelled dashboard origin.

The indicator formats apply a score floor (only sources that *did something*),
because a honeypot sees a lot of harmless background scanning and a blocklist of
every IP that ever touched port 22 mostly blocks researchers and NAT gateways.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session as OrmSession

from pipeline.reporting import export as exporter
from storage.db import get_db

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/blocklist", response_class=PlainTextResponse, summary="Plain IP blocklist")
def blocklist(
    db: OrmSession = Depends(get_db),
    min_score: float = Query(50.0, ge=0, le=100, description="score floor for inclusion"),
    hours: float | None = Query(None, description="only sources seen in the last N hours"),
    comments: bool = Query(True, description="include provenance comments"),
) -> str:
    attackers = exporter.select_indicators(db, min_score=min_score, since_hours=hours)
    return exporter.export_blocklist(attackers, comment=comments)


@router.get("/stix", summary="STIX 2.1 bundle of indicators")
def stix(
    db: OrmSession = Depends(get_db),
    min_score: float = Query(60.0, ge=0, le=100),
    hours: float | None = Query(None),
    sensor: str = Query("honeypot"),
) -> dict:
    import json

    attackers = exporter.select_indicators(db, min_score=min_score, since_hours=hours)
    return json.loads(exporter.export_stix(attackers, sensor=sensor))


@router.get("/misp", summary="MISP event JSON")
def misp(
    db: OrmSession = Depends(get_db),
    min_score: float = Query(60.0, ge=0, le=100),
    hours: float | None = Query(None),
    sensor: str = Query("honeypot"),
) -> dict:
    import json

    attackers = exporter.select_indicators(db, min_score=min_score, since_hours=hours)
    return json.loads(exporter.export_misp(attackers, sensor=sensor))


@router.get("/events.csv", response_class=PlainTextResponse, summary="Events as CSV")
def events_csv(
    db: OrmSession = Depends(get_db),
    hours: float | None = Query(24, gt=0, le=24 * 365),
    limit: int = Query(50000, ge=1, le=500000),
) -> str:
    return exporter.export_events_csv(db, since_hours=hours, limit=limit)


@router.get("/events.jsonl", response_class=PlainTextResponse, summary="Events as JSONL")
def events_jsonl(
    db: OrmSession = Depends(get_db),
    hours: float | None = Query(24, gt=0, le=24 * 365),
    limit: int = Query(50000, ge=1, le=500000),
) -> str:
    """One JSON object per line — the shape most log pipelines ingest directly.

    The exporter existed from the start but was reachable only from the CLI; this
    is the missing route so the whole event stream is pullable over the same
    tunnelled origin as every other export.
    """
    return exporter.export_events_jsonl(db, since_hours=hours, limit=limit)


@router.get("/alerts.csv", response_class=PlainTextResponse, summary="Alerts as CSV")
def alerts_csv(
    db: OrmSession = Depends(get_db),
    hours: float | None = Query(None),
) -> str:
    return exporter.export_alerts_csv(db, since_hours=hours)


__all__ = ["router"]
