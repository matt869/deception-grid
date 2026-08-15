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
from typing import Any, Generic, Literal, TypeVar

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
    src_port: int | None = None
    dst_port: int | None = None
    session_id: str | None = None

    username: str | None = None
    password: str | None = None
    command: str | None = None

    http_method: str | None = None
    path: str | None = None
    user_agent: str | None = None
    status_code: int | None = None

    payload_size: int = 0
    payload_sha256: str | None = None

    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    as_org: str | None = None
    geo_source: str | None = Field(
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
    src_port: int | None = None
    dst_port: int | None = None

    started_at: dt.datetime
    ended_at: dt.datetime | None = None
    duration_ms: int | None = None

    event_count: int = 0
    auth_attempts: int = 0
    commands_run: int = 0
    bytes_in: int = 0

    client_banner: str | None = None
    closed_by: str | None = None
    country: str | None = None
    asn: int | None = None


class SessionSummary(SessionOut):
    """A session listing row.

    ``country_name``/``as_org`` are filled from the session's events rather than
    the sessions table, which the sensor writes before enrichment runs.
    """

    country_name: str | None = None
    as_org: str | None = None


class SessionDetail(SessionSummary):
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

    country: str | None = None
    country_name: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    asn: int | None = None
    as_org: str | None = None

    threat_score: float = 0.0
    classification: str | None = None
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
    score_explanation: ScoreExplanation | None = None


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #


class AlertOut(BaseModel):
    model_config = ORM

    alert_id: str
    rule_id: str
    rule_name: str
    severity: str

    src_ip: str | None = None
    session_id: str | None = None
    service: str | None = None

    title: str
    description: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre: list[str] = Field(default_factory=list)

    first_seen: dt.datetime
    last_seen: dt.datetime
    hit_count: int = 1

    status: str
    notes: str | None = None


class AlertStatusUpdate(BaseModel):
    status: Literal["new", "acknowledged", "closed"]
    notes: str | None = Field(default=None, max_length=4000)


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
    distinct_field: str | None = None
    mitre: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Stats
# --------------------------------------------------------------------------- #


class SummaryStats(BaseModel):
    window_hours: float | None = None
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
    value: str | None = None
    count: int


class CountryRow(BaseModel):
    country: str | None = None
    country_name: str | None = None
    events: int
    attackers: int


class AsnRow(BaseModel):
    asn: int | None = None
    as_org: str | None = None
    events: int
    attackers: int


class ServiceRow(BaseModel):
    service: str
    events: int
    attackers: int


class CredentialPair(BaseModel):
    username: str | None = None
    password: str | None = None
    count: int


class HealthOut(BaseModel):
    status: Literal["ok", "degraded"]
    database: bool
    events_total: int
    latest_event: dt.datetime | None = None
    rules_loaded: int
    geoip_available: bool
    version: str


class EnrichmentOut(BaseModel):
    """On-demand enrichment for an arbitrary IP."""

    src_ip: str
    valid: bool
    scope: str | None = None
    country: str | None = None
    country_name: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    geo_source: str | None = None
    asn: int | None = None
    as_org: str | None = None
    asn_source: str | None = None
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
    "SessionSummary",
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
