"""MySQL emulator (greeting + login capture).

MySQL/MariaDB on 3306 draws constant credential-spraying. Full protocol
emulation means implementing the binary auth exchange; this is deliberately
*minimal* — it sends a realistic server greeting packet, reads the client's
login packet, extracts the username (and records the attempt), then returns an
"access denied" error and closes. That captures the two things worth having from
a 3306 scan — that it happened and which usernames were tried — without the
fragility of a full binary handshake.

The wire format used is the classic ``mysql_native_password`` handshake v10.
Everything read from the client is length-checked; a malformed login packet is
recorded as an error, never a crash.
"""

from __future__ import annotations

import asyncio
import struct

from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

SERVER_VERSION = b"8.0.36-0ubuntu0.22.04.1"
MAX_LOGIN_PACKET = 4096


def _mysql_packet(seq: int, payload: bytes) -> bytes:
    """Wrap a payload in a MySQL packet header (3-byte length + 1-byte seq)."""
    return struct.pack("<I", len(payload))[:3] + bytes([seq & 0xFF]) + payload


def build_handshake() -> bytes:
    """A protocol v10 initial handshake packet."""
    protocol_version = b"\x0a"
    server_version = SERVER_VERSION + b"\x00"
    thread_id = struct.pack("<I", 12345)
    auth_plugin_data_1 = b"\x01\x02\x03\x04\x05\x06\x07\x08"  # 8 bytes salt
    filler = b"\x00"
    capability_low = struct.pack("<H", 0xF7FF)
    charset = b"\x21"  # utf8_general_ci
    status = struct.pack("<H", 0x0002)
    capability_high = struct.pack("<H", 0x81FF)
    auth_plugin_data_len = bytes([21])
    reserved = b"\x00" * 10
    auth_plugin_data_2 = b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x00"
    auth_plugin_name = b"mysql_native_password\x00"

    payload = (
        protocol_version
        + server_version
        + thread_id
        + auth_plugin_data_1
        + filler
        + capability_low
        + charset
        + status
        + capability_high
        + auth_plugin_data_len
        + reserved
        + auth_plugin_data_2
        + auth_plugin_name
    )
    return _mysql_packet(0, payload)


def parse_login_username(packet: bytes) -> str | None:
    """Extract the username from a client login (HandshakeResponse41) packet.

    Layout after the 4-byte packet header: 4 bytes client caps, 4 bytes max
    packet, 1 byte charset, 23 bytes reserved, then the null-terminated username.
    """
    if len(packet) < 4 + 32 + 1:
        return None
    offset = 4 + 4 + 4 + 1 + 23  # header + caps + maxpacket + charset + reserved
    end = packet.find(b"\x00", offset)
    if end == -1 or end - offset > 128:
        return None
    try:
        return packet[offset:end].decode("utf-8", "replace") or None
    except Exception:  # pragma: no cover - defensive
        return None


class MySQLService(BaseService):
    name = "mysql"

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await self.send(writer, build_handshake())

        packet = await self.read_bytes(session, reader, MAX_LOGIN_PACKET)
        if not packet:
            return

        username = parse_login_username(packet)
        if username is not None:
            session.username = username
            session.record(
                EventType.AUTH_ATTEMPT,
                severity=Severity.MEDIUM,
                username=username,
                command="mysql-login",
                tags=["mysql-login"],
                extra={"login_packet_len": len(packet)},
            )
        else:
            session.record(
                EventType.ERROR,
                severity=Severity.LOW,
                tags=["mysql-malformed-login"],
                extra={"bytes": len(packet)},
            )

        # ERR packet: 0xFF, error code 1045, SQLSTATE 28000, "Access denied".
        error_code = struct.pack("<H", 1045)
        sqlstate = b"#28000"
        msg = f"Access denied for user '{username or 'root'}'@'{session.src_ip}' (using password: YES)".encode()
        err_payload = b"\xff" + error_code + sqlstate + msg
        await self.send(writer, _mysql_packet(2, err_payload))


__all__ = ["MySQLService", "build_handshake", "parse_login_username"]
