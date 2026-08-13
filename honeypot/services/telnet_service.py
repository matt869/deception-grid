"""Telnet emulator.

Telnet is where IoT botnets live. Mirai and its descendants sweep 23/tcp with a
short hardcoded credential list, and on success immediately run a recognisable
sequence (``/bin/busybox ECCHI``, ``cat /proc/mounts``, wget of a dropper). That
whole sequence is worth capturing, so this service is generous: it accepts a
login readily and hands the client a fake shell.

The protocol itself is plaintext lines, with one wrinkle — clients negotiate
options using IAC (0xFF) command sequences. Those bytes must be stripped or they
end up inside captured usernames as mojibake.
"""

from __future__ import annotations

import asyncio
import random

from honeypot.deception.responses import FakeShell
from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

# Telnet protocol constants (RFC 854).
IAC = 0xFF
DONT, DO, WONT, WILL = 0xFE, 0xFD, 0xFC, 0xFB
SB, SE = 0xFA, 0xF0

# Credentials that Mirai-class malware carries. Seeing one is a strong signal
# the client is a botnet loader rather than a human or a generic scanner.
IOT_DEFAULT_CREDS: set[tuple[str, str]] = {
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"),
    ("root", "123456"), ("root", "54321"), ("support", "support"), ("root", ""),
    ("admin", "password"), ("root", "root"), ("user", "user"), ("admin", "1234"),
    ("root", "12345"), ("guest", "guest"), ("admin", ""), ("root", "pass"),
}


def strip_telnet_control(raw: bytes) -> bytes:
    """Remove IAC negotiation sequences, returning only user-typed bytes."""
    out = bytearray()
    i = 0
    while i < len(raw):
        byte = raw[i]
        if byte != IAC:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        cmd = raw[i + 1]
        if cmd in (DO, DONT, WILL, WONT):
            i += 3  # IAC + command + option
        elif cmd == SB:
            end = raw.find(bytes([IAC, SE]), i)
            i = len(raw) if end == -1 else end + 2
        elif cmd == IAC:
            out.append(IAC)  # escaped literal 0xFF
            i += 2
        else:
            i += 2
    return bytes(out)


class TelnetService(BaseService):
    name = "telnet"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        # Tell the client we will echo and suppress go-ahead. Real telnetd does
        # this, and its absence is a cheap way to spot an emulator.
        await self.send(writer, bytes([IAC, WILL, 1, IAC, WILL, 3]))
        await self.send(writer, f"{self.persona.telnet_greeting}\r\n")

        rng = random.Random(session.session_id)
        authenticated = False
        username = ""

        for attempt in range(3):
            await self.send(writer, f"{self.hostname} login: ")
            username = await self._read_field(session, reader)
            if username is None:
                return

            await self.send(writer, "Password: ")
            password = await self._read_field(session, reader)
            if password is None:
                return

            is_known_iot = (username, password) in IOT_DEFAULT_CREDS
            severity = Severity.HIGH if is_known_iot else Severity.MEDIUM
            tags = ["iot-default-credential"] if is_known_iot else []

            session.seen_credentials.add((username, password))
            session.record(
                EventType.AUTH_ATTEMPT,
                severity=severity,
                username=username,
                password=password,
                tags=tags,
                extra={"attempt": attempt + 1},
            )

            # Accept readily: the post-login command sequence is the payload of
            # interest for this protocol.
            if is_known_iot or rng.random() < max(self.settings.accept_login_rate, 0.5):
                authenticated = True
                break

            await asyncio.sleep(rng.uniform(0.4, 1.2))  # mimic PAM delay
            await self.send(writer, "\r\nLogin incorrect\r\n")

        if not authenticated:
            await self.send(writer, "\r\nLogin incorrect\r\n")
            return

        session.authenticated = True
        session.username = username
        session.record(
            EventType.AUTH_SUCCESS,
            severity=Severity.HIGH,
            username=username,
            tags=["shell-granted"],
        )

        await self._run_shell(session, reader, writer, username or "root")

    async def _read_field(
        self, session: HoneypotSession, reader: asyncio.StreamReader
    ) -> str | None:
        """Read one line, stripping telnet control bytes."""
        try:
            raw = await asyncio.wait_for(
                reader.readline(), timeout=self.settings.read_timeout_s
            )
        except (asyncio.TimeoutError, ValueError):
            return None
        if not raw:
            return None
        session.count_bytes(len(raw))
        cleaned = strip_telnet_control(raw[: self.settings.max_line_bytes])
        return cleaned.decode("utf-8", "replace").strip("\r\n\x00").strip()

    async def _run_shell(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        username: str,
    ) -> None:
        shell = FakeShell(self.persona, self.hostname, username)
        await self.send(writer, "\r\n" + self.persona.motd.replace("\n", "\r\n"))

        while True:
            await self.send(writer, shell.prompt)
            line = await self._read_field(session, reader)
            if line is None:
                return
            if not line:
                continue

            output = shell.run(line)
            recorded = session.record(
                EventType.COMMAND,
                severity=self._command_severity(line, shell),
                command=line,
                username=username,
                tags=self._command_tags(line, shell),
            )
            if not recorded:
                return  # session event budget exhausted

            if output == "__EXIT__":
                await self.send(writer, "\r\n")
                return
            if output:
                await self.send(writer, output.replace("\n", "\r\n") + "\r\n")

    @staticmethod
    def _command_severity(line: str, shell: FakeShell) -> Severity:
        lowered = line.lower()
        if any(k in lowered for k in ("wget", "curl", "tftp", "busybox", "chmod +x")):
            return Severity.CRITICAL
        if any(k in lowered for k in ("/etc/shadow", "passwd", "authorized_keys")):
            return Severity.HIGH
        return Severity.MEDIUM

    @staticmethod
    def _command_tags(line: str, shell: FakeShell) -> list[str]:
        lowered = line.lower()
        tags: list[str] = []
        if "busybox" in lowered:
            tags.append("mirai-signature")
        if any(k in lowered for k in ("wget", "curl", "tftp")):
            tags.append("payload-fetch")
        if shell.download_attempts:
            tags.append("second-stage-url")
        return tags


__all__ = ["TelnetService", "strip_telnet_control", "IOT_DEFAULT_CREDS"]
