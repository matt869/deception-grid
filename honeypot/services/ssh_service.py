"""SSH emulator.

SSH runs in one of two modes depending on what is installed:

**Fingerprint mode (always available, no extra dependencies).**
Performs the RFC 4253 version exchange, then parses the client's ``SSH_MSG_KEXINIT``
and derives a HASSH fingerprint — an MD5 over the client's offered key-exchange,
cipher, MAC and compression algorithm lists. Because that list is baked into the
client build rather than chosen per-connection, HASSH identifies the *tool*
(libssh-based scanner, Go x/crypto bot, real OpenSSH) even when the version
banner is forged, which it usually is. This mode cannot capture passwords: doing
so requires completing a Diffie-Hellman exchange and decrypting the auth packets.

**Full mode (requires ``paramiko``).**
Completes the transport handshake with a locally generated host key and captures
username/password and public-key attempts before rejecting them, optionally
granting a fake shell.

Fingerprint mode is the default so the sensor has no hard crypto dependency. Run
``pip install paramiko`` to enable credential capture on 22/tcp.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import struct
from pathlib import Path
from typing import Optional

from honeypot.config import PROJECT_ROOT
from honeypot.services.base import BaseService
from honeypot.session import HoneypotSession
from storage.models import EventType, Severity

log = logging.getLogger("honeypot.ssh")

try:  # pragma: no cover - depends on the deployment environment
    import paramiko

    HAS_PARAMIKO = True
except ImportError:  # pragma: no cover
    paramiko = None  # type: ignore[assignment]
    HAS_PARAMIKO = False

SSH_MSG_KEXINIT = 20
HOST_KEY_PATH = PROJECT_ROOT / "data" / "ssh_host_rsa_key"

# Client version strings that belong to mass-scanning tooling rather than to a
# person. Matching is a substring check on the banner.
SCANNER_BANNERS = (
    "libssh", "Go", "paramiko", "PUTTY", "zgrab", "masscan", "nmap",
    "JSCH", "SSH-2.0-Ruby", "russh",
)


# --------------------------------------------------------------------------- #
# HASSH
# --------------------------------------------------------------------------- #


def parse_kexinit(payload: bytes) -> Optional[dict[str, list[str]]]:
    """Parse an ``SSH_MSG_KEXINIT`` payload into its ten algorithm name-lists.

    Returns None if the payload is not a well-formed KEXINIT — hostile input, so
    every length is bounds-checked before use.
    """
    if len(payload) < 17 or payload[0] != SSH_MSG_KEXINIT:
        return None

    offset = 17  # 1 byte message type + 16 byte cookie
    fields = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]

    result: dict[str, list[str]] = {}
    for field in fields:
        if offset + 4 > len(payload):
            return None
        (length,) = struct.unpack(">I", payload[offset : offset + 4])
        offset += 4
        if length > len(payload) - offset:
            return None
        raw = payload[offset : offset + length].decode("utf-8", "replace")
        offset += length
        result[field] = [item for item in raw.split(",") if item]

    return result


def hassh_fingerprint(kex: dict[str, list[str]]) -> tuple[str, str]:
    """Return ``(hassh_md5, hassh_algorithms_string)`` for a parsed KEXINIT.

    Follows the Salesforce HASSH definition: the four client-to-server lists
    joined by semicolons, hashed with MD5. MD5 here is an identifier, not a
    security control — it is the published format and interoperability with
    public HASSH datasets is the whole point.
    """
    algorithms = ";".join(
        [
            ",".join(kex.get("kex_algorithms", [])),
            ",".join(kex.get("encryption_algorithms_client_to_server", [])),
            ",".join(kex.get("mac_algorithms_client_to_server", [])),
            ",".join(kex.get("compression_algorithms_client_to_server", [])),
        ]
    )
    digest = hashlib.md5(algorithms.encode("utf-8"), usedforsecurity=False).hexdigest()
    return digest, algorithms


def classify_banner(banner: str) -> list[str]:
    """Tag a client version string."""
    tags: list[str] = []
    lowered = banner.lower()
    for needle in SCANNER_BANNERS:
        if needle.lower() in lowered:
            tags.append(f"client:{needle.lower()}")
    if not banner.startswith("SSH-2.0-") and not banner.startswith("SSH-1."):
        tags.append("malformed-banner")
    if banner.startswith("SSH-1."):
        tags.append("ssh1-protocol")
    return tags


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class SSHService(BaseService):
    name = "ssh"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._host_key = None
        if HAS_PARAMIKO:
            try:
                self._host_key = _load_or_create_host_key()
            except Exception as exc:  # pragma: no cover
                log.warning("could not prepare SSH host key (%s); falling back to "
                            "fingerprint mode", exc)

    @property
    def full_mode(self) -> bool:
        return HAS_PARAMIKO and self._host_key is not None

    async def start(self) -> None:
        await super().start()
        log.info(
            "ssh running in %s mode%s",
            "full (credential capture)" if self.full_mode else "fingerprint",
            "" if self.full_mode else " — pip install paramiko to capture credentials",
        )

    async def handle_session(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if self.full_mode:
            await self._handle_full(session, reader, writer)
        else:
            await self._handle_fingerprint(session, reader, writer)

    # -- fingerprint mode ------------------------------------------------ #

    async def _handle_fingerprint(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await self.send(writer, f"{self.persona.ssh_version}\r\n")

        client_banner = await self.read_line(session, reader)
        if client_banner is None:
            return
        session.client_banner = client_banner

        tags = classify_banner(client_banner)
        session.record(
            EventType.CONNECT,
            severity=Severity.LOW,
            tags=["ssh-version-exchange", *tags],
            extra={"client_version": client_banner, "mode": "fingerprint"},
        )

        packet = await self._read_binary_packet(session, reader)
        if packet is None:
            return

        kex = parse_kexinit(packet)
        if kex is None:
            session.record(
                EventType.ERROR,
                severity=Severity.LOW,
                tags=["malformed-kexinit"],
                extra={"client_version": client_banner},
            )
            return

        digest, algorithms = hassh_fingerprint(kex)
        session.record(
            EventType.CONNECT,
            severity=Severity.MEDIUM,
            tags=["hassh", *tags],
            extra={
                "client_version": client_banner,
                "hassh": digest,
                "hassh_algorithms": algorithms,
                "kex_algorithms": kex["kex_algorithms"][:12],
                "ciphers": kex["encryption_algorithms_client_to_server"][:12],
                "mode": "fingerprint",
            },
        )

        # Disconnect cleanly rather than hanging: SSH_MSG_DISCONNECT, reason 11
        # (by application). A silent drop looks like a network fault; a proper
        # disconnect looks like a server that declined.
        await self.send(writer, _build_disconnect_packet("No supported authentication methods"))

    async def _read_binary_packet(
        self, session: HoneypotSession, reader: asyncio.StreamReader
    ) -> Optional[bytes]:
        """Read one unencrypted SSH binary packet and return its payload."""
        try:
            header = await asyncio.wait_for(
                reader.readexactly(4), timeout=self.settings.read_timeout_s
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            return None

        (packet_len,) = struct.unpack(">I", header)
        # RFC 4253 caps this at 35000 for the unencrypted phase; anything larger
        # is either broken or an attempt to make us allocate.
        if not 8 <= packet_len <= 35000:
            session.record(
                EventType.ERROR,
                severity=Severity.MEDIUM,
                tags=["oversized-ssh-packet"],
                extra={"declared_length": packet_len},
            )
            return None

        try:
            body = await asyncio.wait_for(
                reader.readexactly(packet_len), timeout=self.settings.read_timeout_s
            )
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError):
            return None

        session.count_bytes(4 + len(body))
        padding_len = body[0]
        if padding_len >= len(body):
            return None
        return body[1 : len(body) - padding_len]

    # -- full mode (paramiko) -------------------------------------------- #

    async def _handle_full(
        self,
        session: HoneypotSession,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:  # pragma: no cover - requires paramiko at runtime
        sock = writer.get_extra_info("socket")
        if sock is None:
            await self._handle_fingerprint(session, reader, writer)
            return

        loop = asyncio.get_running_loop()
        # paramiko is synchronous and takes ownership of the socket, so it runs
        # on the default executor. dup() keeps asyncio's transport teardown from
        # closing the fd out from under it.
        dup_sock = sock.dup()
        try:
            await loop.run_in_executor(None, self._paramiko_session, session, dup_sock)
        finally:
            try:
                dup_sock.close()
            except OSError:
                pass

    def _paramiko_session(self, session: HoneypotSession, sock) -> None:  # pragma: no cover
        transport = paramiko.Transport(sock)
        transport.local_version = "SSH-2.0-" + self.persona.ssh_version.removeprefix("SSH-2.0-")
        transport.add_server_key(self._host_key)
        handler = _ParamikoHandler(self, session)

        try:
            transport.start_server(server=handler)
            channel = transport.accept(timeout=self.settings.read_timeout_s)
            session.client_banner = getattr(transport, "remote_version", None)
            if channel is not None:
                self._serve_fake_shell(session, channel)
        except Exception as exc:
            log.debug("paramiko transport ended for %s: %s", session.src_ip, exc)
        finally:
            try:
                transport.close()
            except Exception:
                pass

    def _serve_fake_shell(self, session: HoneypotSession, channel) -> None:  # pragma: no cover
        from honeypot.deception.responses import FakeShell

        shell = FakeShell(self.persona, self.hostname, session.username or "root")
        channel.send(self.persona.motd.replace("\n", "\r\n").encode())

        buffer = b""
        while True:
            channel.send(shell.prompt.encode())
            buffer = b""
            while not buffer.endswith(b"\n"):
                chunk = channel.recv(1024)
                if not chunk:
                    return
                session.count_bytes(len(chunk))
                buffer += chunk
                channel.send(chunk)  # echo, as a real pty would
                if len(buffer) > self.settings.max_line_bytes:
                    break

            line = buffer.decode("utf-8", "replace").strip()
            if not line:
                continue
            output = shell.run(line)
            if not session.record(
                EventType.COMMAND, severity=Severity.HIGH, command=line,
                username=session.username, tags=["ssh-shell"],
            ):
                return
            if output == "__EXIT__":
                return
            if output:
                channel.send((output.replace("\n", "\r\n") + "\r\n").encode())


if HAS_PARAMIKO:  # pragma: no cover - only defined when paramiko is present

    class _ParamikoHandler(paramiko.ServerInterface):
        """Records every auth attempt, then decides whether to allow it."""

        def __init__(self, service: "SSHService", session: HoneypotSession) -> None:
            self.service = service
            self.session = session
            self._attempts = 0

        def get_allowed_auths(self, username):
            return "password,publickey"

        def check_auth_password(self, username, password):
            import random

            self._attempts += 1
            self.session.username = username
            self.session.seen_credentials.add((username, password))
            self.session.record(
                EventType.AUTH_ATTEMPT,
                severity=Severity.MEDIUM,
                username=username,
                password=password,
                tags=["ssh-password"],
                extra={"attempt": self._attempts},
            )
            rng = random.Random(self.session.session_id + str(self._attempts))
            if rng.random() < self.service.settings.accept_login_rate:
                self.session.authenticated = True
                self.session.record(
                    EventType.AUTH_SUCCESS, severity=Severity.HIGH,
                    username=username, tags=["shell-granted"],
                )
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

        def check_auth_publickey(self, username, key):
            self._attempts += 1
            self.session.record(
                EventType.AUTH_ATTEMPT,
                severity=Severity.MEDIUM,
                username=username,
                tags=["ssh-publickey"],
                extra={
                    "key_type": key.get_name(),
                    "key_fingerprint": key.get_fingerprint().hex(),
                    "attempt": self._attempts,
                },
            )
            return paramiko.AUTH_FAILED

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            self.session.record(
                EventType.CONNECT, severity=Severity.HIGH,
                tags=["channel-request", f"channel:{kind}"],
                extra={"note": "non-session channel refused (would enable tunnelling)"},
            )
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_channel_shell_request(self, channel):
            return True

        def check_channel_pty_request(self, *args, **kwargs):
            return True

        def check_channel_exec_request(self, channel, command):
            self.session.record(
                EventType.COMMAND,
                severity=Severity.CRITICAL,
                command=command.decode("utf-8", "replace"),
                username=self.session.username,
                tags=["ssh-exec"],
            )
            return True

else:  # pragma: no cover

    class _ParamikoHandler:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            raise RuntimeError("paramiko is not installed")


def _load_or_create_host_key():  # pragma: no cover - requires paramiko
    """Load the sensor's SSH host key, generating one on first run."""
    HOST_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    if HOST_KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_PATH))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    log.info("generated new SSH host key at %s", HOST_KEY_PATH)
    return key


def _build_disconnect_packet(message: str) -> bytes:
    """Build an SSH_MSG_DISCONNECT (type 1) binary packet."""
    reason_code = 11  # SSH_DISCONNECT_BY_APPLICATION
    msg = message.encode()
    payload = (
        bytes([1])
        + struct.pack(">I", reason_code)
        + struct.pack(">I", len(msg)) + msg
        + struct.pack(">I", 0)  # empty language tag
    )
    # Packets are padded so (length + padding) is a multiple of 8, min 4 bytes.
    padding_len = 8 - ((len(payload) + 5) % 8)
    if padding_len < 4:
        padding_len += 8
    packet_len = len(payload) + padding_len + 1
    return struct.pack(">I", packet_len) + bytes([padding_len]) + payload + b"\x00" * padding_len


__all__ = [
    "SSHService",
    "parse_kexinit",
    "hassh_fingerprint",
    "classify_banner",
    "HAS_PARAMIKO",
]
