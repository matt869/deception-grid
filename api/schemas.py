"""Pydantic response and request models.

These are the API's contract with the dashboard. They are defined separately
from the ORM models rather than serialising those directly, for two reasons:

* The ORM has fields the API should not expose (surrogate ``id`` columns, raw
  ``extra`` blobs) and shapes the frontend should not depend on. Changing a
  column ought not to be a breaking API change.
* Password fields need policy at the boundary. :class:`EventOut` exposes them
  because credential analysis is the point of this tool, but the redaction
  helper is here, in one place, for deployments that must not serve them.
"""

from __future__ import annotations

import datetime as dt
from typing import Any, Generic, Literal, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")

ORM = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# Envelopes
# --------------------------------------------------------------------------- #


class Page(BaseModel, Generic[T]):
    """Paginated list response."""

    items: list[T]
    total: int = Field(description="Total rows matching the filters, ignoring pagination")
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class Message(BaseModel):
    detail: str


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #


class EventOut(BaseModel):
    model_config = ORM

    event_id: str
    ts: dt.datetime
    sensor: str
    service: str
    event_type: str
    severity: str

    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    session_id: Optional[str] = None

    username: Optional[str] = None
    password: Optional[str] = None
    command: Optional[str] = None

    http_method: Optional[str] = None
    path: Optional[str] = None
    user_agent: Optional[str] = None
    status_code: Optional[int] = None

    payload_size: int = 0
    payload_sha256: Optional[str] = None

    country: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None
    geo_source: Optional[str] = Field(
        default=None,
        description="Where geo data came from. 'synthetic' means generated demo data, "
        "'unavailable' means no lookup was possible — never treat either as a measurement.",
    )

    threat_score: float = 0.0
    threat_tags: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class SessionOut(BaseModel):
    model_config = ORM

    session_id: str
    sensor: str
    service: str
    src_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    started_at: dt.datetime
    ended_at: Optional[dt.datetime] = None
    duration_ms: Optional[int] = None

    event_count: int = 0
    auth_attempts: int = 0
    commands_run: int = 0
    bytes_in: int = 0

    client_banner: Optional[str] = None
    closed_by: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None


class SessionDetail(SessionOut):
    events: list[EventOut] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Attackers
# --------------------------------------------------------------------------- #


class AttackerOut(BaseModel):
    model_config = ORM

    src_ip: str
    first_seen: dt.datetime
    last_seen: dt.datetime

    event_count: int = 0
    session_count: int = 0
    auth_attempts: int = 0
    distinct_usernames: int = 0
    distinct_passwords: int = 0
    commands_run: int = 0

    services: list[str] = Field(default_factory=list)
    top_usernames: list[str] = Field(default_factory=list)
    top_passwords: list[str] = Field(default_factory=list)
    top_paths: list[str] = Field(default_factory=list)

    country: Optional[str] = None
    country_name: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None

    threat_score: float = 0.0
    classification: Optional[str] = None
    tags: list[str] = Field(default_factory=list)
    updated_at: dt.datetime


class ScoreComponents(BaseModel):
    volume: float
    persistence: float
    credential_breadth: float
    service_breadth: float
    severity: float
    post_exploitation: float
    threat_intel: float


class ScoreExplanation(BaseModel):
    """Why an attacker scored what they scored — see pipeline.detection.scoring."""

    score: float
    raw_score: float
    classification: str
    tags: list[str]
    components: ScoreComponents
    weights: dict[str, float]
    recency_decay: float
    age_days: float
    events_considered: int


class AttackerDetail(AttackerOut):
    sessions: list[SessionOut] = Field(default_factory=list)
    recent_events: list[EventOut] = Field(default_factory=list)
    score_explanation: Optional[ScoreExplanation] = None


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #


class AlertOut(BaseModel):
    model_config = ORM

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str

    src_ip: Optional[str] = None
    session_id: Optional[str] = None
    service: Optional[str] = None

    title: str
    description: Optional[str] = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre: list[str] = Field(default_factory=list)

    first_seen: dt.datetime
    last_seen: dt.datetime
    hit_count: int = 1

    status: str
    notes: Optional[str] = None


class AlertStatusUpdate(BaseModel):
    status: Literal["new", "acknowledged", "closed"]
    notes: Optional[str] = Field(default=None, max_length=4000)


class RuleOut(BaseModel):
    id: str
    name: str
    severity: str
    type: str
    description: str = ""
    enabled: bool = True
    window_minutes: int
    group_by: str
    threshold: float
    distinct_field: Optional[str] = None
    mitre: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


class SummaryStats(BaseModel):
    window_hours: Optional[float] = None
    total_events: int
    unique_attackers: int
    unique_countries: int
    sessions: int
    auth_attempts: int
    unique_credential_pairs: int
    commands_run: int
    open_alerts: int
    critical_alerts: int
    generated_at: str


class TimeseriesPoint(BaseModel):
    ts: str
    total: int
    model_config = ConfigDict(extra="allow")  # one key per series


class Timeseries(BaseModel):
    bucket: str
    by: str
    series: list[str]
    points: list[TimeseriesPoint]


class Heatmap(BaseModel):
    since_hours: float
    total: int
    max: int
    weekdays: list[str]
    grid: list[list[int]]


class CountRow(BaseModel):
    value: Optional[str] = None
    count: int


class CountryRow(BaseModel):
    country: Optional[str] = None
    country_name: Optional[str] = None
    events: int
    attackers: int


class AsnRow(BaseModel):
    asn: Optional[int] = None
    as_org: Optional[str] = None
    events: int
    attackers: int


class ServiceRow(BaseModel):
    service: str
    events: int
    attackers: int


class CredentialPair(BaseModel):
    username: Optional[str] = None
    password: Optional[str] = None
    count: int


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    database: bool
    events_total: int
    latest_event: Optional[dt.datetime] = None
    rules_loaded: int
    geoip_available: bool
    version: str


class EnrichmentOut(BaseModel):
    """On-demand enrichment for an arbitrary IP."""

    src_ip: str
    valid: bool
    scope: Optional[str] = None
    country: Optional[str] = None
    country_name: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    geo_source: Optional[str] = None
    asn: Optional[int] = None
    as_org: Optional[str] = None
    asn_source: Optional[str] = None
    threat_score: float = 0.0
    threat_tags: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Policy helper
# --------------------------------------------------------------------------- #

REDACTED = "[redacted]"


def redact_passwords(events: list[EventOut]) -> list[EventOut]:
    """Blank the password field on a list of events.

    Wired to the ``API_REDACT_PASSWORDS`` setting. Captured passwords are
    frequently reused real credentials belonging to real people, so a deployment
    that exposes the dashboard beyond the security team has a good reason to
    turn this on.
    """
    for event in events:
        if event.password:
            event.password = REDACTED
    return events


__all__ = [
    "Page",
    "Message",
    "EventOut",
    "SessionOut",
    "SessionDetail",
    "AttackerOut",
    "AttackerDetail",
    "ScoreExplanation",
    "ScoreComponents",
    "AlertOut",
    "AlertStatusUpdate",
    "RuleOut",
    "SummaryStats",
    "Timeseries",
    "TimeseriesPoint",
    "Heatmap",
    "CountRow",
    "CountryRow",
    "AsnRow",
    "ServiceRow",
    "CredentialPair",
    "HealthOut",
    "EnrichmentOut",
    "redact_passwords",
]
