"""Common asyncio plumbing for every emulated service.

Subclasses implement :meth:`BaseService.handle_session` and get admission
control, session lifecycle, timeouts, byte accounting and error containment for
free.

The error containment matters more than it looks. Every subclass runs against
deliberately hostile input, so ``_handle_client`` treats *any* exception from
``handle_session`` as a normal outcome: log it, record an ``error`` event, close
the socket. One malformed packet must never take down the listener and blind the
sensor.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Optional

from honeypot.config import Settings
from honeypot.deception.banners import Persona, get_persona
from honeypot.logger import EventLogger
from honeypot.session import HoneypotSession, SessionLimitExceeded, SessionRegistry
from storage.models import EventType, Severity

log = logging.getLogger("honeypot.service")


class BaseService(ABC):
    """One listening TCP service."""

    #: Protocol label recorded on every event (matches ``models.Service``).
    name: str = "base"

    def __init__(
        self,
        settings: Settings,
        logger: EventLogger,
        registry: SessionRegistry,
        port: int,
    ) -> None:
        self.settings = settings
        self.logger = logger
        self.registry = registry
        self.port = port
        self.persona: Persona = get_persona(settings.persona)
        self.hostname = settings.hostname
        self._server: Optional[asyncio.AbstractServer] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.settings.bind_host,
            port=self.port,
            reuse_address=True,
        )
        log.info("%s listening on %s:%d", self.name, self.settings.bind_host, self.port)

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        await self._server.wait_closed()
        self._server = None
        log.info("%s stopped", self.name)

    # ------------------------------------------------------------------ #
    # Connection handling
    # ------------------------------------------------------------------ #

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        src_ip, src_port = (peer[0], peer[1]) if peer else ("unknown", 0)

        allowed, reason = self.registry.can_accept(src_ip)
        if not allowed:
            # Close silently. An error message here would tell a scanner it
            # found a rate limiter, which is itself a fingerprint.
            log.debug("rejected %s on %s (%s)", src_ip, self.name, reason)
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            return

        session = HoneypotSession(
            service=self.name,
            src_ip=src_ip,
            src_port=src_port,
            dst_port=self.port,
            logger=self.logger,
            settings=self.settings,
        )
        self.registry.register(session)
        session.open()
        close_reason = "client"

        try:
            await asyncio.wait_for(
                self.handle_session(session, reader, writer),
                timeout=self.settings.session_timeout_s,
            )
        except asyncio.TimeoutError:
            close_reason = "timeout"
        except SessionLimitExceeded as exc:
            close_reason = "limit"
            log.info("%s", exc)
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            close_reason = "client"
        except asyncio.CancelledError:
            close_reason = "server"
            raise
        except Exception as exc:  # noqa: BLE001 - see module docstring
            close_reason = "error"
            log.warning("%s session error from %s: %s", self.name, src_ip, exc, exc_info=True)
            session.record(
                EventType.ERROR,
                severity=Severity.LOW,
                extra={"error": type(exc).__name__, "detail": str(exc)[:500]},
            )
        finally:
            session.close(close_reason)
            self.registry.unregister(session)
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass

    @abstractmethod
    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Run the protocol conversation. Subclass responsibility."""

    # ------------------------------------------------------------------ #
    # I/O helpers
    # ------------------------------------------------------------------ #

    async def send(self, writer: asyncio.StreamWriter, data: str | bytes) -> None:
        payload = data.encode("utf-8", "replace") if isinstance(data, str) else data
        writer.write(payload)
        await writer.drain()

    async def read_line(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        timeout: Optional[float] = None,
    ) -> Optional[str]:
        """Read one CRLF/LF-terminated line.

        Returns None on EOF or timeout. Over-long lines are truncated rather
        than buffered without bound — ``readline`` on a peer that never sends a
        newline is an easy way to exhaust memory.
        """
        limit = self.settings.max_line_bytes
        try:
            raw = await asyncio.wait_for(
                reader.readline(), timeout=timeout or self.settings.read_timeout_s
            )
        except asyncio.TimeoutError:
            return None
        except (asyncio.LimitOverrunError, ValueError):
            # Line exceeded the stream buffer: drain what we can and move on.
            try:
                raw = await asyncio.wait_for(reader.read(limit), timeout=5)
            except (asyncio.TimeoutError, OSError):
                return None

        if not raw:
            return None
        session.count_bytes(len(raw))
        return raw[:limit].decode("utf-8", "replace").rstrip("\r\n")

    async def read_bytes(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        n: int,
        timeout: Optional[float] = None,
    ) -> bytes:
        try:
            data = await asyncio.wait_for(
                reader.read(n), timeout=timeout or self.settings.read_timeout_s
            )
        except asyncio.TimeoutError:
            return b""
        if data:
            session.count_bytes(len(data))
        return data


__all__ = ["BaseService"]
