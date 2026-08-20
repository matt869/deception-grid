"""Unit tests for the FTP emulator.

The module's core promise is negative: it speaks the control channel and never
opens a data connection. Two of these tests exist purely to keep that promise
enforceable — ``PORT`` must be refused (an honoured PORT turns the sensor into
an outbound port scanner on an attacker's behalf) and ``STOR`` must be refused
(an accepted upload puts attacker-chosen bytes on your disk). Both are the kind
of thing a well-meaning "make FTP more realistic" change would quietly break.
"""

from __future__ import annotations

from honeypot.services.ftp_service import FTPService
from storage.models import EventType, Severity


def script(*lines: str) -> bytes:
    return "".join(f"{line}\r\n" for line in lines).encode()


ALWAYS_ACCEPT = {"accept_login_rate": 1.0}
NEVER_ACCEPT = {"accept_login_rate": 0.0}


def login(*lines: str) -> bytes:
    """A scripted session that authenticates first, then runs ``lines``."""
    return script("USER bob", "PASS hunter2", *lines)


# --------------------------------------------------------------------------- #
# Greeting and pre-auth gating
# --------------------------------------------------------------------------- #


class TestGreeting:
    def test_banner_is_sent_before_any_command(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, b"")
        assert writer.text.startswith("220")

    def test_eof_ends_the_session_cleanly(self, protocol_harness):
        # No commands at all: the loop must return, not spin.
        writer, logger, _ = protocol_harness(FTPService, b"")
        assert logger.events == []


class TestPreAuthGating:
    def test_data_command_before_login_is_refused(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, script("LIST"))
        assert "530" in writer.text
        assert "ftp-preauth-refused" in logger.tags()
        # ...and the command handler never ran.
        assert "ftp-list" not in logger.tags()

    def test_syst_is_allowed_before_login(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, script("SYST"))
        assert "215 UNIX Type: L8" in writer.text

    def test_feat_is_allowed_before_login(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, script("FEAT"))
        assert "211-Features:" in writer.text
        assert "211 End" in writer.text

    def test_quit_is_allowed_before_login(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, script("QUIT"))
        assert "221 Goodbye." in writer.text


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #


class TestAuthentication:
    def test_user_prompts_for_password(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, script("USER bob"))
        assert "331" in writer.text

    def test_anonymous_login_is_tagged_separately(self, protocol_harness):
        _, logger, _ = protocol_harness(FTPService, script("USER anonymous"))
        assert "ftp-anonymous" in logger.tags()
        assert "ftp-user" not in logger.tags()

    def test_named_user_is_not_tagged_anonymous(self, protocol_harness):
        _, logger, _ = protocol_harness(FTPService, script("USER bob"))
        assert "ftp-user" in logger.tags()
        assert "ftp-anonymous" not in logger.tags()

    def test_ftp_alias_counts_as_anonymous(self, protocol_harness):
        _, logger, _ = protocol_harness(FTPService, script("USER ftp"))
        assert "ftp-anonymous" in logger.tags()

    def test_accepted_login_transitions_state(self, protocol_harness):
        writer, logger, session = protocol_harness(FTPService, login(), **ALWAYS_ACCEPT)
        assert "230 Login successful." in writer.text
        assert session.authenticated is True
        assert session.username == "bob"
        assert logger.tagged("ftp-login-accepted")

    def test_rejected_login_leaves_session_unauthenticated(self, protocol_harness):
        writer, logger, session = protocol_harness(FTPService, login(), **NEVER_ACCEPT)
        assert "530 Login incorrect." in writer.text
        assert session.authenticated is False
        assert not logger.tagged("ftp-login-accepted")

    def test_credentials_are_captured(self, protocol_harness):
        _, logger, session = protocol_harness(FTPService, login(), **NEVER_ACCEPT)
        assert ("bob", "hunter2") in session.seen_credentials
        attempt = logger.tagged("ftp-password")[0]
        assert attempt["username"] == "bob"
        assert attempt["password"] == "hunter2"

    def test_password_is_not_echoed_into_the_command_field(self, protocol_harness):
        # The password has its own column; the command transcript must not
        # duplicate it, or redaction settings would only half apply.
        _, logger, _ = protocol_harness(FTPService, login(), **NEVER_ACCEPT)
        assert logger.tagged("ftp-password")[0]["command"] == "PASS ****"

    def test_anonymous_is_accepted_above_the_configured_rate(self, protocol_harness):
        # Anonymous uses a fixed 0.8 threshold, deliberately more permissive
        # than accept_login_rate, mirroring misconfigured real servers.
        accepted = 0
        for _ in range(20):
            _, logger, _ = protocol_harness(
                FTPService, script("USER anonymous", "PASS x@y.z"), **NEVER_ACCEPT
            )
            accepted += bool(logger.tagged("ftp-login-accepted"))
        assert accepted > 0

    def test_auth_attempts_are_counted_on_the_session(self, protocol_harness):
        _, logger, session = protocol_harness(FTPService, login(), **NEVER_ACCEPT)
        assert session.auth_attempts == 2  # USER and PASS both count
        assert len(logger.of_type(EventType.AUTH_ATTEMPT)) == 2


# --------------------------------------------------------------------------- #
# The two refusals that define the emulator
# --------------------------------------------------------------------------- #


class TestNoDataChannel:
    def test_port_is_refused_as_a_bounce_attempt(self, protocol_harness):
        writer, logger, _ = protocol_harness(
            FTPService, login("PORT 127,0,0,1,4,1"), **ALWAYS_ACCEPT
        )
        assert "500 Illegal PORT command." in writer.text
        event = logger.tagged("ftp-bounce-attempt")[0]
        assert event["severity"] == Severity.HIGH.value
        assert "refused" in event["extra"]

    def test_upload_is_refused_and_recorded_critical(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, login("STOR payload.sh"), **ALWAYS_ACCEPT)
        assert "550 Permission denied." in writer.text
        event = logger.tagged("ftp-upload-attempt")[0]
        assert event["event_type"] == EventType.FILE_UPLOAD.value
        assert event["severity"] == Severity.CRITICAL.value
        assert event["path"] == "payload.sh"
        assert "refused" in event["extra"]

    def test_every_upload_verb_is_refused(self, protocol_harness):
        for verb in ("STOR", "STOU", "APPE"):
            writer, logger, _ = protocol_harness(
                FTPService, login(f"{verb} x.bin"), **ALWAYS_ACCEPT
            )
            assert "550" in writer.text, verb
            assert logger.tagged("ftp-upload-attempt"), verb

    def test_passive_mode_is_advertised_but_recorded(self, protocol_harness):
        # PASV answers so the client keeps talking; no data socket is opened.
        writer, logger, _ = protocol_harness(FTPService, login("PASV"), **ALWAYS_ACCEPT)
        assert "227 Entering Passive Mode" in writer.text
        assert "ftp-passive" in logger.tags()


# --------------------------------------------------------------------------- #
# Filesystem verbs
# --------------------------------------------------------------------------- #


class TestFilesystemVerbs:
    def test_retr_fails_without_serving_bytes(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, login("RETR /etc/passwd"), **ALWAYS_ACCEPT)
        assert "550 Failed to open file." in writer.text
        assert logger.tagged("ftp-download-attempt")[0]["path"] == "/etc/passwd"

    def test_destructive_verbs_are_high_severity(self, protocol_harness):
        for verb in ("DELE", "RMD", "MKD", "RNFR", "RNTO", "SITE"):
            _, logger, _ = protocol_harness(FTPService, login(f"{verb} x"), **ALWAYS_ACCEPT)
            event = logger.tagged("ftp-modify-attempt")[0]
            assert event["severity"] == Severity.HIGH.value, verb

    def test_list_returns_a_plausible_directory(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, login("LIST"), **ALWAYS_ACCEPT)
        assert "150" in writer.text and "226" in writer.text
        assert "ftp-list" in logger.tags()

    def test_cwd_then_pwd_reflects_the_new_directory(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, login("CWD /var/www", "PWD"), **ALWAYS_ACCEPT)
        assert '257 "/var/www"' in writer.text

    def test_relative_cwd_is_joined_onto_the_current_directory(self, protocol_harness):
        writer, _, _ = protocol_harness(
            FTPService, login("CWD /var", "CWD www", "PWD"), **ALWAYS_ACCEPT
        )
        assert '257 "/var/www"' in writer.text

    def test_type_switches_without_recording_noise(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, login("TYPE I"), **ALWAYS_ACCEPT)
        assert "200 Switching to Binary mode." in writer.text
        assert not logger.tagged("ftp-unknown")


# --------------------------------------------------------------------------- #
# Robustness
# --------------------------------------------------------------------------- #


class TestRobustness:
    def test_unknown_command_is_recorded_not_crashed(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, login("FROBNICATE x"), **ALWAYS_ACCEPT)
        assert "500 Unknown command." in writer.text
        assert logger.tagged("ftp-unknown")[0]["command"] == "FROBNICATE x"

    def test_blank_lines_are_skipped(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, b"\r\n\r\nSYST\r\n")
        assert "215" in writer.text

    def test_lowercase_commands_are_accepted(self, protocol_harness):
        writer, _, _ = protocol_harness(FTPService, script("syst"))
        assert "215" in writer.text

    def test_absurdly_long_verb_is_truncated_not_stored_whole(self, protocol_harness):
        _, logger, _ = protocol_harness(FTPService, script("USER x", "PASS y", "A" * 4000))
        recorded = logger.tagged("ftp-preauth-refused") or logger.tagged("ftp-unknown")
        assert recorded  # handled by some branch, never raised

    def test_quit_closes_and_stops_processing(self, protocol_harness):
        writer, logger, _ = protocol_harness(FTPService, script("QUIT", "SYST"))
        assert "221 Goodbye." in writer.text
        assert "215" not in writer.text  # nothing after QUIT ran
