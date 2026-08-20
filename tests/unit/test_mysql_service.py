"""Unit tests for the MySQL emulator.

The emulator is deliberately minimal — greeting, capture the username, deny —
and that narrowness is what these tests protect. Its whole value is the two
facts worth having from a 3306 scan: that it happened, and which usernames were
tried. A malformed login packet must therefore still be *recorded* rather than
dropped, because "someone spoke almost-MySQL at us" is itself the observation.

The handshake is checked byte by byte because a client that cannot parse the
greeting hangs up before sending credentials, and the sensor then captures
nothing at all while appearing to work.
"""

from __future__ import annotations

import struct

import pytest

from honeypot.services.mysql_service import (
    MAX_LOGIN_PACKET,
    SERVER_VERSION,
    MySQLService,
    build_handshake,
    parse_login_username,
)
from storage.models import EventType, Severity


def login_packet(username: str, *, caps: int = 0x000A_A28D, seq: int = 1) -> bytes:
    """A HandshakeResponse41 packet carrying ``username``."""
    payload = (
        struct.pack("<I", caps)
        + struct.pack("<I", 16_777_216)  # max packet size
        + bytes([0x21])  # charset
        + b"\x00" * 23  # reserved
        + username.encode()
        + b"\x00"
        + b"\x14"
        + b"\xaa" * 20  # auth response
    )
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


# --------------------------------------------------------------------------- #
# Handshake
# --------------------------------------------------------------------------- #


class TestHandshake:
    def test_packet_length_header_matches_the_payload(self):
        # A wrong length makes a real client hang waiting for bytes that never
        # arrive, and the sensor captures nothing.
        packet = build_handshake()
        declared = int.from_bytes(packet[:3], "little")
        assert declared == len(packet) - 4

    def test_sequence_number_is_zero(self):
        assert build_handshake()[3] == 0

    def test_protocol_version_is_ten(self):
        assert build_handshake()[4] == 0x0A

    def test_server_version_is_advertised_and_null_terminated(self):
        payload = build_handshake()[4:]
        assert payload[1 : 1 + len(SERVER_VERSION)] == SERVER_VERSION
        assert payload[1 + len(SERVER_VERSION)] == 0

    def test_advertises_native_password_auth(self):
        assert b"mysql_native_password\x00" in build_handshake()

    def test_handshake_is_stable_across_calls(self):
        # A greeting that changed per connection would be a fingerprint.
        assert build_handshake() == build_handshake()


# --------------------------------------------------------------------------- #
# Login parsing
# --------------------------------------------------------------------------- #


class TestParseLoginUsername:
    @pytest.mark.parametrize("username", ["root", "admin", "mysql", "a", "x" * 100])
    def test_extracts_the_username(self, username):
        assert parse_login_username(login_packet(username)) == username

    def test_non_ascii_username_is_decoded_not_dropped(self):
        assert parse_login_username(login_packet("wörker")) == "wörker"

    def test_short_packet_returns_none(self):
        assert parse_login_username(b"\x00" * 10) is None

    def test_empty_packet_returns_none(self):
        assert parse_login_username(b"") is None

    def test_missing_null_terminator_returns_none(self):
        # 'x' repeated with no terminator: must not run off the end.
        payload = struct.pack("<I", 0) + struct.pack("<I", 0) + bytes([0x21]) + b"\x00" * 23
        assert parse_login_username(b"\x00" * 4 + payload + b"x" * 50) is None

    def test_absurdly_long_username_is_rejected(self):
        # >128 bytes before the terminator is not a username, it is a payload.
        assert parse_login_username(login_packet("x" * 400)) is None

    def test_empty_username_reads_as_none(self):
        assert parse_login_username(login_packet("")) is None


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #


class TestSession:
    def test_greeting_is_sent_immediately(self, protocol_harness):
        writer, _, _ = protocol_harness(MySQLService, b"")
        assert writer.chunks[0] == build_handshake()

    def test_client_that_hangs_up_records_nothing_extra(self, protocol_harness):
        _, logger, _ = protocol_harness(MySQLService, b"")
        assert logger.events == []

    def test_login_is_captured(self, protocol_harness):
        _, logger, session = protocol_harness(MySQLService, login_packet("root"))
        event = logger.tagged("mysql-login")[0]
        assert event["event_type"] == EventType.AUTH_ATTEMPT.value
        assert event["username"] == "root"
        assert session.username == "root"

    def test_login_records_the_packet_length(self, protocol_harness):
        packet = login_packet("admin")
        _, logger, _ = protocol_harness(MySQLService, packet)
        assert logger.tagged("mysql-login")[0]["extra"]["login_packet_len"] == len(packet)

    def test_malformed_login_is_recorded_not_dropped(self, protocol_harness):
        # "Someone spoke almost-MySQL at us" is the observation worth keeping.
        _, logger, _ = protocol_harness(MySQLService, b"\x05\x00\x00\x01hello")
        event = logger.tagged("mysql-malformed-login")[0]
        assert event["event_type"] == EventType.ERROR.value
        assert event["severity"] == Severity.LOW.value
        assert event["extra"]["bytes"] > 0

    def test_access_denied_is_returned(self, protocol_harness):
        writer, _, _ = protocol_harness(MySQLService, login_packet("root"))
        assert b"\xff" in writer.chunks[-1]
        assert b"Access denied" in writer.chunks[-1]

    def test_error_packet_names_the_attempted_user(self, protocol_harness):
        writer, _, _ = protocol_harness(MySQLService, login_packet("oracle"))
        assert b"'oracle'@" in writer.chunks[-1]

    def test_error_packet_falls_back_to_root_when_unparsed(self, protocol_harness):
        writer, _, _ = protocol_harness(MySQLService, b"\x05\x00\x00\x01hello")
        assert b"'root'@" in writer.chunks[-1]

    def test_error_packet_carries_the_1045_code_and_sqlstate(self, protocol_harness):
        writer, _, _ = protocol_harness(MySQLService, login_packet("root"))
        err = writer.chunks[-1]
        body = err[4:]
        assert body[0] == 0xFF
        assert struct.unpack("<H", body[1:3])[0] == 1045
        assert body[3:9] == b"#28000"

    def test_error_packet_length_header_is_correct(self, protocol_harness):
        writer, _, _ = protocol_harness(MySQLService, login_packet("root"))
        err = writer.chunks[-1]
        assert int.from_bytes(err[:3], "little") == len(err) - 4

    def test_oversized_login_does_not_exhaust_memory(self, protocol_harness):
        # read_bytes is capped; a client claiming a huge packet gets truncated
        # rather than buffered.
        _, logger, session = protocol_harness(
            MySQLService, login_packet("root") + b"\x00" * (MAX_LOGIN_PACKET * 4)
        )
        assert session.bytes_in <= MAX_LOGIN_PACKET

    def test_binary_garbage_does_not_raise(self, protocol_harness):
        protocol_harness(MySQLService, bytes(range(256)) * 4)

    def test_session_records_one_auth_attempt(self, protocol_harness):
        _, logger, session = protocol_harness(MySQLService, login_packet("root"))
        assert session.auth_attempts == 1
        assert len(logger.of_type(EventType.AUTH_ATTEMPT)) == 1
