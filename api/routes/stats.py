"""Aggregate statistics — everything the overview page charts."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import (
    AsnRow,
    CountRow,
    CountryRow,
    CredentialPair,
    EnrichmentOut,
    Heatmap,
    ServiceRow,
    SummaryStats,
    Timeseries,
)
from storage import queries
from storage.db import get_db

router = APIRouter(prefix="/stats", tags=["stats"])

DEFAULT_WINDOW = 24.0
MAX_WINDOW = 24 * 365.0


@router.get("/summary", response_model=SummaryStats, summary="Headline counters")
def summary(
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
) -> SummaryStats:
    return SummaryStats(**queries.summary_stats(db, since_hours=hours))


@router.get("/timeseries", response_model=Timeseries, summary="Bucketed event counts")
def timeseries(
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
    bucket: str = Query("1h", description="1m | 5m | 15m | 1h | 6h | 1d"),
    by: str = Query("service", description="service | severity | event_type | none"),
) -> Timeseries:
    if bucket not in queries.BUCKETS:
        raise HTTPException(400, f"unknown bucket {bucket!r}; use one of {sorted(queries.BUCKETS)}")
    if by not in ("service", "severity", "event_type", "none"):
        raise HTTPException(400, f"cannot split by {by!r}")

    # Guard against a request that would generate an unreasonable number of
    # points — 1-minute buckets over a year is 525,600 rows nobody can render.
    bucket_count = (hours * 3600) / queries.BUCKETS[bucket].total_seconds()
    if bucket_count > 5000:
        raise HTTPException(
            400,
            f"window of {hours:g}h at bucket {bucket} would produce {int(bucket_count):,} points; "
            "use a coarser bucket or a shorter window",
        )

    return Timeseries(**queries.events_timeseries(db, since_hours=hours, bucket=bucket, by=by))


@router.get("/heatmap", response_model=Heatmap, summary="Activity by weekday and UTC hour")
def heatmap(
    db: OrmSession = Depends(get_db),
    hours: float = Query(24 * 14, gt=0, le=MAX_WINDOW),
) -> Heatmap:
    return Heatmap(**queries.hour_weekday_heatmap(db, since_hours=hours))


@router.get("/services", response_model=list[ServiceRow], summary="Events per service")
def services(
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
) -> list[ServiceRow]:
    return [ServiceRow(**row) for row in queries.service_breakdown(db, since_hours=hours)]


@router.get("/countries", response_model=list[CountryRow], summary="Events per country")
def countries(
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
    limit: int = Query(50, ge=1, le=250),
) -> list[CountryRow]:
    return [CountryRow(**row) for row in queries.top_countries(db, limit=limit, since_hours=hours)]


@router.get("/asns", response_model=list[AsnRow], summary="Events per network")
def asns(
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
    limit: int = Query(20, ge=1, le=200),
) -> list[AsnRow]:
    return [AsnRow(**row) for row in queries.top_asns(db, limit=limit, since_hours=hours)]


@router.get("/top/{field}", response_model=list[CountRow], summary="Top values for a field")
def top_field(
    field: str,
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
    limit: int = Query(20, ge=1, le=200),
) -> list[CountRow]:
    """One endpoint for the several "top N" tables, keyed by field name."""
    handlers = {
        "usernames": queries.top_usernames,
        "passwords": queries.top_passwords,
        "paths": queries.top_paths,
        "commands": queries.top_commands,
        "user_agents": queries.top_user_agents,
    }
    handler = handlers.get(field)
    if handler is None:
        raise HTTPException(400, f"unknown field {field!r}; use one of {sorted(handlers)}")
    return [CountRow(**row) for row in handler(db, limit=limit, since_hours=hours)]


@router.get("/credentials", response_model=list[CredentialPair], summary="Top credential pairs")
def credentials(
    db: OrmSession = Depends(get_db),
    hours: float = Query(DEFAULT_WINDOW, gt=0, le=MAX_WINDOW),
    limit: int = Query(100, ge=1, le=500),
) -> list[CredentialPair]:
    return [
        CredentialPair(**row)
        for row in queries.credential_pairs(db, limit=limit, since_hours=hours)
    ]


@router.get("/enrich/{ip}", response_model=EnrichmentOut, summary="Enrich an arbitrary IP")
def enrich(ip: str) -> EnrichmentOut:
    """Run the enrichment pipeline against one address.

    Reads only from local databases and indicator files — see
    ``pipeline.enrichment.threat_intel`` for why this never queries a third
    party.
    """
    from pipeline.enrichment import enrich_ip

    result = enrich_ip(ip)
    if not result.get("valid"):
        raise HTTPException(400, f"{ip!r} is not a valid IP address")
    return EnrichmentOut(**{k: v for k, v in result.items() if k in EnrichmentOut.model_fields})


__all__ = ["router"]
