"""Redis emulator.

Exposed Redis is one of the most-scanned services on the internet: an
unauthenticated instance can be turned into remote code execution by writing an
SSH key or a cron job via ``CONFIG SET dir`` + ``SET`` + ``SAVE``, or hijacked
with ``SLAVEOF``/``REPLICAOF`` and ``MODULE LOAD``. This emulator speaks enough
of RESP to keep that playbook running so the whole sequence is captured — and,
like every service here, it executes nothing and writes nothing.

It parses both RESP arrays (``*3\r\n$3\r\nSET\r\n...``) and inline commands, with
every length bounds-checked before allocation.
"""

from __future__ import annotations

import asyncio

from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

MAX_BULK_LEN = 64 * 1024
MAX_ARRAY_LEN = 1024

# Commands that indicate an RCE / persistence attempt rather than benign probing.
DANGEROUS = {
    "config": "redis-config-abuse",
    "slaveof": "redis-replication-hijack",
    "replicaof": "redis-replication-hijack",
    "module": "redis-module-load",
    "eval": "redis-lua-eval",
    "evalsha": "redis-lua-eval",
    "save": "redis-persist",
    "bgsave": "redis-persist",
    "debug": "redis-debug",
    "migrate": "redis-migrate",
    "restore": "redis-restore",
}


class RedisService(BaseService):
    name = "redis"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # Real attackers routinely skip AUTH entirely (the whole point is finding
        # an *unauthenticated* Redis), so commands are served regardless.
        for _ in range(200):
            command = await self._read_command(session, reader)
            if command is None:
                return
            if not command:
                continue

            verb = command[0].lower()
            args = command[1:]

            if verb == "auth":
                # AUTH [user] pass — capture the credential(s).
                username = args[0] if len(args) >= 2 else None
                password = args[-1] if args else ""
                session.record(
                    EventType.AUTH_ATTEMPT,
                    severity=Severity.MEDIUM,
                    username=username,
                    password=password,
                    command="AUTH",
                    tags=["redis-auth"],
                )
                await self.send(writer, "+OK\r\n")
                continue

            tags = ["redis-command"]
            severity = Severity.LOW
            if verb in DANGEROUS:
                tags.append(DANGEROUS[verb])
                tags.append("redis-dangerous")  # shared tag the detection rule matches
                severity = (
                    Severity.CRITICAL
                    if verb in {"config", "module", "eval", "slaveof", "replicaof"}
                    else Severity.HIGH
                )

            # Writing a key whose value looks like an SSH key or cron line is the
            # actual payload of the classic Redis RCE.
            joined = " ".join(command)
            if verb == "set" and any(
                k in joined for k in ("ssh-rsa", "ssh-ed25519", "* * * * *", "/etc/cron")
            ):
                tags.append("redis-rce-payload")
                severity = Severity.CRITICAL

            recorded = session.record(
                EventType.COMMAND,
                severity=severity,
                command=self._safe_command(command),
                tags=tags,
            )
            if not recorded:
                return

            await self.send(writer, self._reply(verb, args))
            if verb == "quit":
                return

    # ------------------------------------------------------------------ #

    async def _read_command(
        self, session: HoneypotSession, reader: asyncio.StreamReader
    ) -> list[str] | None:
        """Read one command (RESP array or inline). None on EOF/timeout."""
        line = await self.read_line(session, reader)
        if line is None:
            return None
        line = line.strip()
        if not line:
            return []

        if not line.startswith("*"):
            return line.split()  # inline command

        try:
            count = int(line[1:])
        except ValueError:
            return []
        if count <= 0 or count > MAX_ARRAY_LEN:
            return []

        parts: list[str] = []
        for _ in range(count):
            header = await self.read_line(session, reader)
            if header is None or not header.startswith("$"):
                return parts
            try:
                length = int(header[1:])
            except ValueError:
                return parts
            if length < 0 or length > MAX_BULK_LEN:
                return parts
            data = await self.read_bytes(session, reader, length + 2)  # value + CRLF
            parts.append(data[:length].decode("utf-8", "replace"))
        return parts

    def _reply(self, verb: str, args: list[str]) -> str:
        if verb == "ping":
            return "+PONG\r\n"
        if verb == "quit":
            return "+OK\r\n"
        if verb == "info":
            return self._bulk(_FAKE_INFO)
        if verb == "select":
            return "+OK\r\n"
        if verb in (
            "set",
            "config",
            "slaveof",
            "replicaof",
            "flushall",
            "flushdb",
            "save",
            "bgsave",
        ):
            return "+OK\r\n"
        if verb == "get":
            return "$-1\r\n"  # nil
        if verb == "command":
            return "*0\r\n"
        if verb in ("dbsize",):
            return ":0\r\n"
        if verb == "module":
            return "-ERR unknown command or module unavailable\r\n"
        return "+OK\r\n"

    @staticmethod
    def _bulk(text: str) -> str:
        encoded = text.replace("\n", "\r\n")
        return f"${len(encoded)}\r\n{encoded}\r\n"

    @staticmethod
    def _safe_command(command: list[str]) -> str:
        # Truncate each argument so a giant SET value can't dominate storage.
        return " ".join(a[:256] for a in command)[:2048]


_FAKE_INFO = (
    "# Server\r\n"
    "redis_version:6.0.16\r\n"
    "redis_mode:standalone\r\n"
    "os:Linux 5.15.0-91-generic x86_64\r\n"
    "arch_bits:64\r\n"
    "process_id:1\r\n"
    "run_id:8b3f2c1a9d4e5f6071829384a5b6c7d8e9f01234\r\n"
    "tcp_port:6379\r\n"
    "uptime_in_seconds:4128301\r\n"
    "# Clients\r\nconnected_clients:1\r\n"
    "# Memory\r\nused_memory_human:1.02M\r\nmaxmemory_human:0B\r\n"
    "# Persistence\r\nloading:0\r\nrdb_bgsave_in_progress:0\r\n"
    "# Keyspace\r\n"
)


__all__ = ["RedisService", "DANGEROUS"]
