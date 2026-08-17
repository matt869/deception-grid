"""Honeypot configuration.

Deliberately built on ``dataclasses`` + ``os.environ`` rather than
pydantic-settings: the honeypot process should have the smallest possible
dependency surface, since it is the one component that terminates hostile
connections.

Every setting is overridable by environment variable so the same image works in
docker-compose and on a bare host. See ``.env.example`` for the full list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env_str(key: str, default: str) -> str:
    value = os.getenv(key)
    return default if value is None or value == "" else value


def _env_int(key: str, default: int) -> int:
    raw = os.getenv(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{key} must be an integer, got {raw!r}") from exc


def _env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(key: str, default: list[str]) -> list[str]:
    raw = os.getenv(key)
    if raw is None or raw == "":
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(slots=True)
class ServiceConfig:
    """Bind settings for one emulated service."""

    name: str
    enabled: bool
    port: int
    banner: str = ""

    @property
    def label(self) -> str:
        return f"{self.name}:{self.port}"


@dataclass(slots=True)
class Settings:
    # -- identity -----------------------------------------------------------
    sensor_name: str = field(default_factory=lambda: _env_str("SENSOR_NAME", "default"))
    bind_host: str = field(default_factory=lambda: _env_str("HONEYPOT_BIND", "0.0.0.0"))

    # -- emulated services --------------------------------------------------
    # High ports by default so the process never needs root. Map 22->2222 etc.
    # at the firewall or in docker-compose if you want real-world traffic.
    ssh_enabled: bool = field(default_factory=lambda: _env_bool("SSH_ENABLED", True))
    ssh_port: int = field(default_factory=lambda: _env_int("SSH_PORT", 2222))
    telnet_enabled: bool = field(default_factory=lambda: _env_bool("TELNET_ENABLED", True))
    telnet_port: int = field(default_factory=lambda: _env_int("TELNET_PORT", 2323))
    ftp_enabled: bool = field(default_factory=lambda: _env_bool("FTP_ENABLED", True))
    ftp_port: int = field(default_factory=lambda: _env_int("FTP_PORT", 2121))
    http_enabled: bool = field(default_factory=lambda: _env_bool("HTTP_ENABLED", True))
    http_port: int = field(default_factory=lambda: _env_int("HTTP_PORT", 8081))
    redis_enabled: bool = field(default_factory=lambda: _env_bool("REDIS_ENABLED", True))
    redis_port: int = field(default_factory=lambda: _env_int("REDIS_PORT", 6379))
    mysql_enabled: bool = field(default_factory=lambda: _env_bool("MYSQL_ENABLED", True))
    mysql_port: int = field(default_factory=lambda: _env_int("MYSQL_PORT", 3306))
    # An exposed Docker daemon is host-takeover-by-design, not an exploit — the
    # single highest-signal bait in the set.
    docker_enabled: bool = field(default_factory=lambda: _env_bool("DOCKER_ENABLED", True))
    docker_port: int = field(default_factory=lambda: _env_int("DOCKER_PORT", 2375))

    # -- deception ----------------------------------------------------------
    # The persona every service presents. See honeypot/deception/banners.py.
    persona: str = field(default_factory=lambda: _env_str("HONEYPOT_PERSONA", "ubuntu-generic"))
    hostname: str = field(default_factory=lambda: _env_str("HONEYPOT_HOSTNAME", "srv-web-04"))
    # Fraction of logins to "accept" so we can observe post-auth behaviour.
    # 0.0 = never accept (pure credential collection).
    accept_login_rate: float = field(
        default_factory=lambda: float(_env_str("ACCEPT_LOGIN_RATE", "0.15"))
    )

    # -- connection limits --------------------------------------------------
    # These exist to protect the sensor, not the attacker. An unbounded
    # honeypot is a free amplifier and a free way to fill your disk.
    max_connections: int = field(default_factory=lambda: _env_int("MAX_CONNECTIONS", 500))
    max_connections_per_ip: int = field(
        default_factory=lambda: _env_int("MAX_CONNECTIONS_PER_IP", 20)
    )
    session_timeout_s: int = field(default_factory=lambda: _env_int("SESSION_TIMEOUT", 120))
    read_timeout_s: int = field(default_factory=lambda: _env_int("READ_TIMEOUT", 30))
    max_line_bytes: int = field(default_factory=lambda: _env_int("MAX_LINE_BYTES", 8192))
    max_session_bytes: int = field(
        default_factory=lambda: _env_int("MAX_SESSION_BYTES", 1024 * 512)
    )
    max_events_per_session: int = field(
        default_factory=lambda: _env_int("MAX_EVENTS_PER_SESSION", 500)
    )

    # -- capture ------------------------------------------------------------
    capture_payloads: bool = field(default_factory=lambda: _env_bool("CAPTURE_PAYLOADS", True))
    payload_dir: Path = field(
        default_factory=lambda: Path(
            _env_str("PAYLOAD_DIR", str(PROJECT_ROOT / "data" / "payloads"))
        )
    )
    # Never store passwords in cleartext? Off by default because credential
    # analysis is the point of this sensor, but regulated deployments flip it.
    hash_passwords: bool = field(default_factory=lambda: _env_bool("HASH_PASSWORDS", False))

    # -- storage / logging --------------------------------------------------
    jsonl_path: Path | None = field(
        default_factory=lambda: Path(
            _env_str("JSONL_PATH", str(PROJECT_ROOT / "data" / "events.jsonl"))
        )
    )
    write_to_db: bool = field(default_factory=lambda: _env_bool("WRITE_TO_DB", True))
    log_level: str = field(default_factory=lambda: _env_str("LOG_LEVEL", "INFO"))
    enrich_inline: bool = field(default_factory=lambda: _env_bool("ENRICH_INLINE", True))

    # -- allowlist ----------------------------------------------------------
    # Source IPs that are never recorded (your own scanners, uptime checks).
    ignore_ips: list[str] = field(default_factory=lambda: _env_list("IGNORE_IPS", []))

    def services(self) -> list[ServiceConfig]:
        return [
            ServiceConfig("ssh", self.ssh_enabled, self.ssh_port),
            ServiceConfig("telnet", self.telnet_enabled, self.telnet_port),
            ServiceConfig("ftp", self.ftp_enabled, self.ftp_port),
            ServiceConfig("http", self.http_enabled, self.http_port),
            ServiceConfig("redis", self.redis_enabled, self.redis_port),
            ServiceConfig("mysql", self.mysql_enabled, self.mysql_port),
            ServiceConfig("docker", self.docker_enabled, self.docker_port),
        ]

    def enabled_services(self) -> list[ServiceConfig]:
        return [s for s in self.services() if s.enabled]

    def validate(self) -> None:
        """Fail fast on configuration that would misbehave at runtime."""
        errors: list[str] = []

        if not 0.0 <= self.accept_login_rate <= 1.0:
            errors.append(f"ACCEPT_LOGIN_RATE must be in [0, 1], got {self.accept_login_rate}")

        enabled = self.enabled_services()
        if not enabled:
            errors.append("no services enabled; set at least one of SSH/TELNET/FTP/HTTP_ENABLED")

        ports = [s.port for s in enabled]
        duplicates = {p for p in ports if ports.count(p) > 1}
        if duplicates:
            errors.append(f"duplicate ports across enabled services: {sorted(duplicates)}")

        for port in ports:
            if not 1 <= port <= 65535:
                errors.append(f"port out of range: {port}")

        if self.max_connections_per_ip > self.max_connections:
            errors.append(
                "MAX_CONNECTIONS_PER_IP cannot exceed MAX_CONNECTIONS "
                f"({self.max_connections_per_ip} > {self.max_connections})"
            )

        if errors:
            raise ValueError("invalid honeypot configuration:\n  - " + "\n  - ".join(errors))

    def ensure_dirs(self) -> None:
        if self.capture_payloads:
            self.payload_dir.mkdir(parents=True, exist_ok=True)
        if self.jsonl_path is not None:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    """Build and validate settings from the current environment."""
    settings = Settings()
    settings.validate()
    settings.ensure_dirs()
    return settings


__all__ = ["Settings", "ServiceConfig", "load_settings", "PROJECT_ROOT"]
