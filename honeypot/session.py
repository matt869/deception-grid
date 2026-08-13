"""Per-connection session state and the global connection registry.

A :class:`HoneypotSession` is the unit that ties every event from one TCP
conversation together. It also enforces the per-session budgets from
:class:`~honeypot.config.Settings` — byte and event caps — so a single attacker
holding a socket open and screaming into it cannot fill the disk.

:class:`SessionRegistry` owns admission control: global and per-IP concurrent
connection limits. Both matter. The global cap protects the sensor; the per-IP
cap stops one noisy source from starving every other observation.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from honeypot.config import Settings
from honeypot.logger import EventLogger
from storage.models import EventType, Severity, utcnow

log = logging.getLogger("honeypot.session")


class SessionLimitExceeded(Exception):
    """Raised inside a session when a configured budget is exhausted."""


@dataclass(slots=True)
class HoneypotSession:
    service: str
    src_ip: str
    src_port: int
    dst_port: int
    logger: EventLogger
    settings: Settings

    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: dt.datetime = field(default_factory=utcnow)

    event_count: int = 0
    auth_attempts: int = 0
    commands_run: int = 0
    bytes_in: int = 0
    client_banner: Optional[str] = None
    closed_by: Optional[str] = None

    # Credentials seen this session, so a service can decide whether to "accept"
    # a login it has already rejected — inconsistency is a tell.
    seen_credentials: set = field(default_factory=set)
    authenticated: bool = False
    username: Optional[str] = None

    # ------------------------------------------------------------------ #

    def open(self) -> None:
        """Record the session row and the initial connect event."""
        self.logger.emit_session(
            {
                "session_id": self.session_id,
                "sensor": self.settings.sensor_name,
                "service": self.service,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "started_at": self.started_at,
            }
        )
        self.record(EventType.CONNECT, severity=Severity.INFO)

    def close(self, reason: str = "client") -> None:
        """Record the disconnect event and finalise the session row."""
        self.closed_by = reason
        ended = utcnow()
        duration_ms = int((ended - self.started_at).total_seconds() * 1000)

        self.record(EventType.DISCONNECT, severity=Severity.INFO, extra={"reason": reason})
        self.logger.emit_session(
            {
                "session_id": self.session_id,
                "ended_at": ended,
                "duration_ms": duration_ms,
                "event_count": self.event_count,
                "auth_attempts": self.auth_attempts,
                "commands_run": self.commands_run,
                "bytes_in": self.bytes_in,
                "client_banner": self.client_banner,
                "closed_by": reason,
            }
        )

    # ------------------------------------------------------------------ #

    def record(
        self,
        event_type: EventType | str,
        *,
        severity: Severity | str = Severity.INFO,
        username: Optional[str] = None,
        password: Optional[str] = None,
        command: Optional[str] = None,
        http_method: Optional[str] = None,
        path: Optional[str] = None,
        user_agent: Optional[str] = None,
        status_code: Optional[int] = None,
        headers: Optional[dict[str, str]] = None,
        payload_sha256: Optional[str] = None,
        payload_size: int = 0,
        tags: Optional[list[str]] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> bool:
        """Emit one event for this session.

        Returns False if the session's event budget is exhausted — callers use
        that as the signal to hang up rather than keep serving a flood.
        """
        if self.event_count >= self.settings.max_events_per_session:
            return False

        etype = event_type.value if isinstance(event_type, EventType) else event_type
        sev = severity.value if isinstance(severity, Severity) else severity

        if etype == EventType.AUTH_ATTEMPT.value:
            self.auth_attempts += 1
        elif etype == EventType.COMMAND.value:
            self.commands_run += 1

        self.event_count += 1
        self.logger.emit(
            {
                "session_id": self.session_id,
                "service": self.service,
                "event_type": etype,
                "severity": sev,
                "src_ip": self.src_ip,
                "src_port": self.src_port,
                "dst_port": self.dst_port,
                "username": username,
                "password": password,
                "command": command,
                "http_method": http_method,
                "path": path,
                "user_agent": user_agent,
                "status_code": status_code,
                "headers": headers,
                "payload_sha256": payload_sha256,
                "payload_size": payload_size,
                "tags": tags or [],
                "extra": extra or {},
            }
        )
        return True

    def count_bytes(self, n: int) -> None:
        """Track inbound volume and trip the session budget when exceeded."""
        self.bytes_in += n
        if self.bytes_in > self.settings.max_session_bytes:
            raise SessionLimitExceeded(
                f"session {self.session_id[:8]} exceeded {self.settings.max_session_bytes} bytes"
            )

    @property
    def peer(self) -> str:
        return f"{self.src_ip}:{self.src_port}"


class SessionRegistry:
    """Admission control and live-session bookkeeping."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._active: dict[str, HoneypotSession] = {}
        self._per_ip: dict[str, int] = {}
        self.rejected_global = 0
        self.rejected_per_ip = 0
        self.total_accepted = 0

    def can_accept(self, src_ip: str) -> tuple[bool, str]:
        if src_ip in self.settings.ignore_ips:
            return False, "ignored"
        if len(self._active) >= self.settings.max_connections:
            self.rejected_global += 1
            return False, "global_limit"
        if self._per_ip.get(src_ip, 0) >= self.settings.max_connections_per_ip:
            self.rejected_per_ip += 1
            return False, "per_ip_limit"
        return True, "ok"

    def register(self, session: HoneypotSession) -> None:
        self._active[session.session_id] = session
        self._per_ip[session.src_ip] = self._per_ip.get(session.src_ip, 0) + 1
        self.total_accepted += 1

    def unregister(self, session: HoneypotSession) -> None:
        self._active.pop(session.session_id, None)
        remaining = self._per_ip.get(session.src_ip, 1) - 1
        if remaining <= 0:
            self._per_ip.pop(session.src_ip, None)
        else:
            self._per_ip[session.src_ip] = remaining

    @property
    def active_count(self) -> int:
        return len(self._active)

    @property
    def active_ips(self) -> int:
        return len(self._per_ip)

    def stats(self) -> dict[str, int]:
        return {
            "active_sessions": self.active_count,
            "active_ips": self.active_ips,
            "total_accepted": self.total_accepted,
            "rejected_global": self.rejected_global,
            "rejected_per_ip": self.rejected_per_ip,
        }


__all__ = ["HoneypotSession", "SessionRegistry", "SessionLimitExceeded"]
