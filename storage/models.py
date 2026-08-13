"""SQLAlchemy ORM models for the honeypot datastore.

The schema is deliberately denormalised in two places:

* ``Event`` carries a flattened copy of its enrichment (country, ASN, threat
  score). Events are written once and read constantly by the dashboard, so
  paying the storage cost beats joining three tables on every query.
* ``Attacker`` is a rolling aggregate over events keyed by source IP. It is
  rebuilt by :func:`storage.queries.rebuild_attackers` rather than maintained
  transactionally, which keeps the honeypot's hot path to a single INSERT.

Everything works on SQLite (the default) and PostgreSQL without change.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import Any, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    """Timezone-aware UTC now.

    ``datetime.utcnow`` is deprecated in 3.12 and returns a naive value, which
    silently breaks comparisons against the aware timestamps we store.
    """
    return dt.datetime.now(dt.timezone.utc)


def ensure_utc(value: Optional[dt.datetime]) -> Optional[dt.datetime]:
    """Normalise a datetime read back from the database to aware UTC.

    SQLite has no timestamp type, so SQLAlchemy hands back *naive* datetimes
    even for ``DateTime(timezone=True)`` columns. Comparing one of those to
    :func:`utcnow` raises ``TypeError``. Every read path funnels through here.
    """
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc)


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# Enumerations
#
# Stored as plain strings rather than native DB enums: adding a service or an
# event type should never require a migration.
# --------------------------------------------------------------------------- #


class Service(str, enum.Enum):
    SSH = "ssh"
    TELNET = "telnet"
    FTP = "ftp"
    HTTP = "http"


class EventType(str, enum.Enum):
    CONNECT = "connect"
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_SUCCESS = "auth_success"  # emitted when a service fakes an accept
    COMMAND = "command"
    HTTP_REQUEST = "http_request"
    FILE_UPLOAD = "file_upload"
    DISCONNECT = "disconnect"
    ERROR = "error"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class AlertStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    CLOSED = "closed"


# --------------------------------------------------------------------------- #
# Core tables
# --------------------------------------------------------------------------- #


class Event(Base):
    """A single observed interaction with a honeypot service."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    ts: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )

    # -- provenance ---------------------------------------------------------
    session_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("sessions.session_id", ondelete="CASCADE"), index=True
    )
    sensor: Mapped[str] = mapped_column(String(64), default="default", index=True)
    service: Mapped[str] = mapped_column(String(16), index=True)
    event_type: Mapped[str] = mapped_column(String(32), index=True)

    # -- network ------------------------------------------------------------
    src_ip: Mapped[str] = mapped_column(String(45), index=True)  # 45 = max IPv6 len
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    transport: Mapped[str] = mapped_column(String(8), default="tcp")

    # -- credentials --------------------------------------------------------
    username: Mapped[Optional[str]] = mapped_column(String(256), index=True)
    password: Mapped[Optional[str]] = mapped_column(String(256), index=True)

    # -- shell / command activity -------------------------------------------
    command: Mapped[Optional[str]] = mapped_column(Text)

    # -- http ---------------------------------------------------------------
    http_method: Mapped[Optional[str]] = mapped_column(String(16))
    path: Mapped[Optional[str]] = mapped_column(Text, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text)
    status_code: Mapped[Optional[int]] = mapped_column(Integer)
    headers: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON)

    # -- payload ------------------------------------------------------------
    payload_size: Mapped[int] = mapped_column(Integer, default=0)
    payload_sha256: Mapped[Optional[str]] = mapped_column(String(64), index=True)

    # -- enrichment (flattened, see module docstring) -----------------------
    country: Mapped[Optional[str]] = mapped_column(String(2), index=True)
    country_name: Mapped[Optional[str]] = mapped_column(String(64))
    city: Mapped[Optional[str]] = mapped_column(String(128))
    latitude: Mapped[Optional[float]] = mapped_column(Float)
    longitude: Mapped[Optional[float]] = mapped_column(Float)
    asn: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    as_org: Mapped[Optional[str]] = mapped_column(String(256))
    geo_source: Mapped[Optional[str]] = mapped_column(String(32))

    threat_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    threat_tags: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)

    # -- classification -----------------------------------------------------
    severity: Mapped[str] = mapped_column(String(16), default=Severity.INFO.value, index=True)
    tags: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)
    extra: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=dict)

    session: Mapped[Optional["Session"]] = relationship(back_populates="events")

    __table_args__ = (
        # The dashboard's two hottest access patterns: "recent activity for one
        # attacker" and "recent activity on one service".
        Index("ix_events_src_ip_ts", "src_ip", "ts"),
        Index("ix_events_service_ts", "service", "ts"),
        Index("ix_events_ts_severity", "ts", "severity"),
    )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Event {self.event_type} {self.service} {self.src_ip} @ {self.ts}>"


class Session(Base):
    """One TCP conversation between an attacker and one honeypot service."""

    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    sensor: Mapped[str] = mapped_column(String(64), default="default")
    service: Mapped[str] = mapped_column(String(16), index=True)
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[Optional[int]] = mapped_column(Integer)
    dst_port: Mapped[Optional[int]] = mapped_column(Integer)

    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    ended_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[Optional[int]] = mapped_column(Integer)

    event_count: Mapped[int] = mapped_column(Integer, default=0)
    auth_attempts: Mapped[int] = mapped_column(Integer, default=0)
    commands_run: Mapped[int] = mapped_column(Integer, default=0)
    bytes_in: Mapped[int] = mapped_column(Integer, default=0)

    client_banner: Mapped[Optional[str]] = mapped_column(Text)
    closed_by: Mapped[Optional[str]] = mapped_column(String(16))  # client|server|timeout

    country: Mapped[Optional[str]] = mapped_column(String(2), index=True)
    asn: Mapped[Optional[int]] = mapped_column(Integer)

    events: Mapped[list[Event]] = relationship(
        back_populates="session", cascade="all, delete-orphan", passive_deletes=True
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Session {self.service} {self.src_ip} events={self.event_count}>"


class Attacker(Base):
    """Rolling per-source-IP aggregate.

    Rebuilt from ``events``; never the source of truth. Dropping this table and
    re-running :func:`storage.queries.rebuild_attackers` is always safe.
    """

    __tablename__ = "attackers"

    src_ip: Mapped[str] = mapped_column(String(45), primary_key=True)

    first_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)

    event_count: Mapped[int] = mapped_column(Integer, default=0, index=True)
    session_count: Mapped[int] = mapped_column(Integer, default=0)
    auth_attempts: Mapped[int] = mapped_column(Integer, default=0)
    distinct_usernames: Mapped[int] = mapped_column(Integer, default=0)
    distinct_passwords: Mapped[int] = mapped_column(Integer, default=0)
    commands_run: Mapped[int] = mapped_column(Integer, default=0)

    services: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)
    top_usernames: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)
    top_passwords: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)
    top_paths: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)

    country: Mapped[Optional[str]] = mapped_column(String(2), index=True)
    country_name: Mapped[Optional[str]] = mapped_column(String(64))
    latitude: Mapped[Optional[float]] = mapped_column(Float)
    longitude: Mapped[Optional[float]] = mapped_column(Float)
    asn: Mapped[Optional[int]] = mapped_column(Integer, index=True)
    as_org: Mapped[Optional[str]] = mapped_column(String(256))

    threat_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    classification: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    tags: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)

    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Attacker {self.src_ip} score={self.threat_score:.1f}>"


class Alert(Base):
    """A detection-rule hit.

    ``dedupe_key`` collapses a repeating condition into one row so the analyst
    sees "brute force from 10.0.0.5" once with a hit counter, not 400 times.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(16), index=True)

    src_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    session_id: Mapped[Optional[str]] = mapped_column(String(36), index=True)
    service: Mapped[Optional[str]] = mapped_column(String(16), index=True)

    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[Optional[str]] = mapped_column(Text)
    evidence: Mapped[Optional[dict[str, Any]]] = mapped_column(JSON, default=dict)
    mitre: Mapped[Optional[list[str]]] = mapped_column(JSON, default=list)

    first_seen: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    hit_count: Mapped[int] = mapped_column(Integer, default=1)

    status: Mapped[str] = mapped_column(String(16), default=AlertStatus.NEW.value, index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text)

    dedupe_key: Mapped[str] = mapped_column(String(256), index=True)

    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_alerts_dedupe_key"),
        Index("ix_alerts_status_sev", "status", "severity"),
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Alert {self.rule_id} {self.src_ip} x{self.hit_count}>"


class Indicator(Base):
    """A local threat-intel indicator.

    Populated from files under ``data/`` — this project never calls out to a
    third-party feed unless you explicitly run the refresh tool.
    """

    __tablename__ = "indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True)  # ip|cidr|asn|ua|path
    value: Mapped[str] = mapped_column(String(256), index=True)
    source: Mapped[str] = mapped_column(String(64))
    category: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    added_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    __table_args__ = (UniqueConstraint("kind", "value", "source", name="uq_indicator"),)

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Indicator {self.kind}:{self.value} ({self.source})>"


__all__ = [
    "Base",
    "Event",
    "Session",
    "Attacker",
    "Alert",
    "Indicator",
    "Service",
    "EventType",
    "Severity",
    "AlertStatus",
    "utcnow",
    "ensure_utc",
]
