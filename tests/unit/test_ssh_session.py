"""Unit tests for the SSH emulator's fingerprint-mode session.

``test_services.py`` covers the pure helpers — ``parse_kexinit``,
``hassh_fingerprint``, ``classify_banner``. What was untested is the
conversation that feeds them: the version exchange, reading one unencrypted
binary packet off the wire, and the disconnect.

That packet reader is the part worth guarding. It takes a 32-bit length
straight from the client and then allocates against it, so the bounds check is
the only thing between a hostile four bytes and the sensor trying to read four
gigabytes. RFC 4253 caps the unencrypted phase at 35000, and anything outside
that is recorded as an event rather than silently dropped — a client declaring
a four-gigabyte packet is itself worth knowing about.

These run in fingerprint mode, which is what the sensor uses when paramiko is
absent. Full mode needs a real socket and is marked no-cover in the module.
"""

from __future__ import annotations

import struct

import pytest

from honeypot.services.ssh_service import SSH_MSG_KEXINIT, SSHService
from storage.models import EventType, Severity

DEFAULT_KEX = ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"]
DEFAULT_CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes256-gcm@openssh.com"]
DEFAULT_MACS = ["umac-64-etm@openssh.com", "hmac-sha2-256"]
DEFAULT_COMP = ["none", "zlib@openssh.com"]


def kexinit_payload(
    kex: list[str] | None = None,
    ciphers: list[str] | None = None,
    macs: list[str] | None = None,
    compression: list[str] | None = None,
) -> bytes:
    """A well-formed SSH_MSG_KEXINIT payload with all ten name-lists."""
    lists = [
        kex if kex is not None else DEFAULT_KEX,
        ["rsa-sha2-512", "ssh-ed25519"],
        ciphers if ciphers is not None else DEFAULT_CIPHERS,
        ciphers if ciphers is not None else DEFAULT_CIPHERS,
        macs if macs is not None else DEFAULT_MACS,
        macs if macs is not None else DEFAULT_MACS,
        compression if compression is not None else DEFAULT_COMP,
        compression if compression is not None else DEFAULT_COMP,
        [],
        [],
    ]
    parts = [bytes([SSH_MSG_KEXINIT]), b"\x00" * 16]
    for names in lists:
        raw = ",".join(names).encode()
        parts.append(struct.pack(">I", len(raw)) + raw)
    parts.append(b"\x00" + b"\x00" * 4)  # first_kex_packet_follows + reserved
    return b"".join(parts)


def binary_packet(payload: bytes, padding: int = 8) -> bytes:
    """Wrap a payload as an unencrypted SSH binary packet."""
    body = bytes([padding]) + payload + b"\x00" * padding
    return struct.pack(">I", len(body)) + body


def banner(text: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4") -> bytes:
    return f"{text}\r\n".encode()


@pytest.fixture
def fingerprint_only(monkeypatch):
    """Pin fingerprint mode regardless of whether paramiko is installed."""
    monkeypatch.setattr(SSHService, "full_mode", property(lambda self: False))


# --------------------------------------------------------------------------- #
# Version exchange
# --------------------------------------------------------------------------- #


class TestVersionExchange:
    def test_server_banner_is_sent_first(self, protocol_harness, fingerprint_only):
        writer, _, _ = protocol_harness(SSHService, b"")
        assert writer.text.startswith("SSH-")

    def test_client_banner_is_recorded(self, protocol_harness, fingerprint_only):
        _, logger, session = protocol_harness(SSHService, banner())
        assert session.client_banner.startswith("SSH-2.0-OpenSSH_8.9p1")
        event = logger.tagged("ssh-version-exchange")[0]
        assert event["extra"]["mode"] == "fingerprint"
        assert "OpenSSH_8.9p1" in event["extra"]["client_version"]

    def test_scanner_banner_is_tagged(self, protocol_harness, fingerprint_only):
        _, logger, _ = protocol_harness(SSHService, banner("SSH-2.0-Go"))
        assert "client:go" in logger.tags()

    def test_malformed_banner_is_tagged(self, protocol_harness, fingerprint_only):
        _, logger, _ = protocol_harness(SSHService, banner("GET / HTTP/1.1"))
        assert "malformed-banner" in logger.tags()

    def test_ssh1_client_is_tagged(self, protocol_harness, fingerprint_only):
        _, logger, _ = protocol_harness(SSHService, banner("SSH-1.99-OpenSSH_3.9"))
        assert "ssh1-protocol" in logger.tags()

    def test_client_that_sends_nothing_records_nothing(self, protocol_harness, fingerprint_only):
        _, logger, _ = protocol_harness(SSHService, b"")
        assert logger.events == []

    def test_banner_without_a_kexinit_still_records_the_connect(
        self, protocol_harness, fingerprint_only
    ):
        # A scanner that grabs the version string and hangs up is the single
        # most common thing on port 22. It must still be captured.
        _, logger, _ = protocol_harness(SSHService, banner())
        assert len(logger.tagged("ssh-version-exchange")) == 1


# --------------------------------------------------------------------------- #
# HASSH
# --------------------------------------------------------------------------- #


class TestHasshCapture:
    def test_kexinit_produces_a_hassh_event(self, protocol_harness, fingerprint_only):
        _, logger, _ = protocol_harness(SSHService, banner() + binary_packet(kexinit_payload()))
        event = logger.tagged("hassh")[0]
        assert event["severity"] == Severity.MEDIUM.value
        assert len(event["extra"]["hassh"]) == 32  # md5 hex
        assert event["extra"]["kex_algorithms"][0] == "curve25519-sha256"

    def test_hassh_is_stable_for_the_same_client(self, protocol_harness, fingerprint_only):
        script = banner() + binary_packet(kexinit_payload())
        first = protocol_harness(SSHService, script)[1].tagged("hassh")[0]["extra"]["hassh"]
        second = protocol_harness(SSHService, script)[1].tagged("hassh")[0]["extra"]["hassh"]
        assert first == second

    def test_different_algorithms_give_a_different_hassh(self, protocol_harness, fingerprint_only):
        # That is the entire point: the fingerprint tracks the client build,
        # not the address it came from.
        a = protocol_harness(SSHService, banner() + binary_packet(kexinit_payload()))
        b = protocol_harness(
            SSHService, banner() + binary_packet(kexinit_payload(ciphers=["aes128-cbc"]))
        )
        assert (
            a[1].tagged("hassh")[0]["extra"]["hassh"] != (b[1].tagged("hassh")[0]["extra"]["hassh"])
        )

    def test_banner_tags_carry_onto_the_hassh_event(self, protocol_harness, fingerprint_only):
        _, logger, _ = protocol_harness(
            SSHService, banner("SSH-2.0-zgrab") + binary_packet(kexinit_payload())
        )
        assert "client:zgrab" in logger.tagged("hassh")[0]["tags"]

    def test_algorithm_lists_are_truncated_in_the_record(self, protocol_harness, fingerprint_only):
        many = [f"kex-{i}" for i in range(40)]
        _, logger, _ = protocol_harness(
            SSHService, banner() + binary_packet(kexinit_payload(kex=many))
        )
        assert len(logger.tagged("hassh")[0]["extra"]["kex_algorithms"]) == 12

    def test_disconnect_is_sent_rather_than_hanging_up(self, protocol_harness, fingerprint_only):
        # A silent drop looks like a network fault; a real disconnect looks
        # like a server that declined.
        writer, _, _ = protocol_harness(SSHService, banner() + binary_packet(kexinit_payload()))
        assert b"No supported authentication methods" in b"".join(writer.chunks)


# --------------------------------------------------------------------------- #
# The binary packet reader, against hostile lengths
# --------------------------------------------------------------------------- #


class TestBinaryPacketReader:
    def test_absurd_declared_length_is_refused_and_recorded(
        self, protocol_harness, fingerprint_only
    ):
        # Four bytes claiming a 4 GB packet. Recording it matters: a client
        # that does this is not a client.
        script = banner() + struct.pack(">I", 0xFFFFFFFF) + b"\x00" * 16
        _, logger, _ = protocol_harness(SSHService, script)
        event = logger.tagged("oversized-ssh-packet")[0]
        assert event["event_type"] == EventType.ERROR.value
        assert event["severity"] == Severity.MEDIUM.value
        assert event["extra"]["declared_length"] == 0xFFFFFFFF

    def test_length_just_over_the_rfc_cap_is_refused(self, protocol_harness, fingerprint_only):
        script = banner() + struct.pack(">I", 35001) + b"\x00" * 32
        _, logger, _ = protocol_harness(SSHService, script)
        assert logger.tagged("oversized-ssh-packet")

    def test_length_at_the_cap_is_accepted(self, protocol_harness, fingerprint_only):
        payload = kexinit_payload()
        body = bytes([8]) + payload + b"\x00" * 8
        script = banner() + struct.pack(">I", len(body)) + body
        _, logger, _ = protocol_harness(SSHService, script)
        assert not logger.tagged("oversized-ssh-packet")

    def test_undersized_length_is_refused(self, protocol_harness, fingerprint_only):
        script = banner() + struct.pack(">I", 4) + b"\x00" * 4
        _, logger, _ = protocol_harness(SSHService, script)
        assert logger.tagged("oversized-ssh-packet")

    def test_truncated_body_does_not_raise(self, protocol_harness, fingerprint_only):
        # Declares 100 bytes, sends 10, then EOF.
        script = banner() + struct.pack(">I", 100) + b"\x00" * 10
        _, logger, _ = protocol_harness(SSHService, script)
        assert not logger.tagged("hassh")

    def test_truncated_header_does_not_raise(self, protocol_harness, fingerprint_only):
        protocol_harness(SSHService, banner() + b"\x00\x00")

    def test_padding_longer_than_the_body_is_refused(self, protocol_harness, fingerprint_only):
        # padding_len >= len(body) would slice into nonsense.
        body = bytes([200]) + b"\x00" * 20
        script = banner() + struct.pack(">I", len(body)) + body
        _, logger, _ = protocol_harness(SSHService, script)
        assert not logger.tagged("hassh")

    def test_non_kexinit_payload_is_recorded_as_malformed(self, protocol_harness, fingerprint_only):
        script = banner() + binary_packet(b"\x63" + b"\x00" * 40)  # wrong message type
        _, logger, _ = protocol_harness(SSHService, script)
        event = logger.tagged("malformed-kexinit")[0]
        assert event["event_type"] == EventType.ERROR.value

    def test_kexinit_with_a_truncated_name_list_is_malformed(
        self, protocol_harness, fingerprint_only
    ):
        # Declares a 9999-byte list that is not there.
        payload = bytes([SSH_MSG_KEXINIT]) + b"\x00" * 16 + struct.pack(">I", 9999) + b"abc"
        _, logger, _ = protocol_harness(SSHService, banner() + binary_packet(payload))
        assert logger.tagged("malformed-kexinit")

    def test_bytes_are_counted_against_the_session_budget(self, protocol_harness, fingerprint_only):
        _, _, session = protocol_harness(SSHService, banner() + binary_packet(kexinit_payload()))
        assert session.bytes_in > 0

    def test_random_binary_does_not_raise(self, protocol_harness, fingerprint_only):
        protocol_harness(SSHService, banner() + bytes(range(256)) * 8)
