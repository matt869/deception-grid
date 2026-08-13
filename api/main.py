"""FastAPI application.

    uvicorn api.main:app --reload --port 8000

Serves the dashboard's read API plus a small number of operational endpoints
(re-run detection, rebuild aggregates, update alert status).

**On authentication:** there is none, by design and with a caveat. This API is
meant to sit on a private network or behind an authenticating reverse proxy, and
shipping a hand-rolled auth layer would be worse than shipping none — it invites
being trusted. The app refuses to bind a non-loopback interface with a
permissive CORS origin unless you set ``API_ALLOW_INSECURE=1``, so the unsafe
configuration is at least a deliberate act. See README "Deployment safety".
"""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import alerts, attackers, events, stats
from api.schemas import HealthOut

log = logging.getLogger("api")

VERSION = "1.0.0"
DEFAULT_CORS_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173"


def _cors_origins() -> list[str]:
    raw = os.getenv("API_CORS_ORIGINS", DEFAULT_CORS_ORIGINS)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


def _check_deployment_safety() -> None:
    """Refuse the one configuration that is silently dangerous.

    A wildcard CORS origin on an API with no authentication means any page the
    analyst visits can read the whole honeypot dataset — including captured
    credentials — out of their browser. That is worth stopping at startup.
    """
    origins = _cors_origins()
    if "*" not in origins:
        return
    if os.getenv("API_ALLOW_INSECURE", "").strip().lower() in {"1", "true", "yes", "on"}:
        log.warning(
            "API_CORS_ORIGINS=* with no authentication — permitted because "
            "API_ALLOW_INSECURE is set. Do not expose this beyond a trusted network."
        )
        return
    raise RuntimeError(
        "API_CORS_ORIGINS=* is refused: this API has no authentication, so a wildcard "
        "origin lets any site the analyst visits read captured credentials. "
        "Set explicit origins, or set API_ALLOW_INSECURE=1 if you understand the risk."
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-7s %(name)-16s %(message)s",
    )
    _check_deployment_safety()

    from storage.db import database_url, init_db

    init_db()
    log.info("api %s ready (database: %s)", VERSION, _safe_url(database_url()))

    yield

    log.info("api shutting down")


def _safe_url(url: str) -> str:
    """Strip credentials from a database URL before logging it."""
    if "@" in url and "//" in url:
        scheme, _, rest = url.partition("//")
        _, _, host = rest.rpartition("@")
        return f"{scheme}//***@{host}"
    return url


app = FastAPI(
    title="Honeypot Dashboard API",
    description=(
        "Read API over honeypot observations: events, sessions, attackers and alerts.\n\n"
        "**Data handling note.** Responses may contain credentials submitted by "
        "attackers. Those are frequently real credentials reused from breaches and "
        "belonging to real people. Set `API_REDACT_PASSWORDS=1` to blank them."
    ),
    version=VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_timing_header(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["X-Response-Time-ms"] = f"{elapsed_ms:.1f}"
    if elapsed_ms > 1000:
        log.warning("slow request %s %s took %.0fms", request.method, request.url.path, elapsed_ms)
    return response


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Turn query-layer ValueErrors into 400s rather than 500s."""
    return JSONResponse(status_code=400, content={"detail": str(exc)})


api_prefix = "/api"
app.include_router(events.router, prefix=api_prefix)
app.include_router(events.sessions_router, prefix=api_prefix)
app.include_router(stats.router, prefix=api_prefix)
app.include_router(attackers.router, prefix=api_prefix)
app.include_router(alerts.router, prefix=api_prefix)


@app.get("/api/health", response_model=HealthOut, tags=["meta"], summary="Health check")
def health() -> HealthOut:
    """Liveness plus a few facts worth knowing before trusting the data."""
    from sqlalchemy import func, select

    from pipeline.enrichment import geoip
    from storage.db import session_scope
    from storage.models import Event

    database_ok = True
    total = 0
    latest = None
    try:
        with session_scope() as db:
            total = db.execute(select(func.count()).select_from(Event)).scalar_one()
            latest = db.execute(select(func.max(Event.ts))).scalar_one()
    except Exception as exc:
        log.error("health check database probe failed: %s", exc)
        database_ok = False

    try:
        from pipeline.detection.rules import load_rules

        rules_loaded = len(load_rules())
    except Exception:
        rules_loaded = 0

    return HealthOut(
        status="ok" if database_ok and rules_loaded else "degraded",
        database=database_ok,
        events_total=int(total),
        latest_event=latest,
        rules_loaded=rules_loaded,
        geoip_available=geoip._get_reader() is not None,
        version=VERSION,
    )


@app.get("/", tags=["meta"], summary="Service index")
def index() -> dict:
    return {
        "service": "honeypot-dashboard-api",
        "version": VERSION,
        "docs": "/docs",
        "health": "/api/health",
        "endpoints": [
            "/api/events",
            "/api/events/live",
            "/api/sessions/{id}",
            "/api/stats/summary",
            "/api/stats/timeseries",
            "/api/stats/heatmap",
            "/api/attackers",
            "/api/attackers/map",
            "/api/attackers/{ip}",
            "/api/alerts",
            "/api/alerts/rules",
        ],
    }


__all__ = ["app"]
