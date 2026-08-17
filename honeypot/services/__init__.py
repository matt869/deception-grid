"""Emulated network services."""

from honeypot.services.base import BaseService
from honeypot.services.docker_service import DockerService
from honeypot.services.ftp_service import FTPService
from honeypot.services.http_service import HTTPService
from honeypot.services.mysql_service import MySQLService
from honeypot.services.redis_service import RedisService
from honeypot.services.ssh_service import SSHService
from honeypot.services.telnet_service import TelnetService

#: Maps the service name used in config and events to its implementation.
SERVICE_REGISTRY: dict[str, type[BaseService]] = {
    "ssh": SSHService,
    "telnet": TelnetService,
    "ftp": FTPService,
    "http": HTTPService,
    "redis": RedisService,
    "mysql": MySQLService,
    "docker": DockerService,
}

__all__ = [
    "BaseService",
    "SSHService",
    "TelnetService",
    "FTPService",
    "HTTPService",
    "RedisService",
    "MySQLService",
    "DockerService",
    "SERVICE_REGISTRY",
]
