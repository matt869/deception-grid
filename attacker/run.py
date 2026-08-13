"""Traffic generator for exercising a running honeypot.

    python -m attacker.run --target 127.0.0.1 --scenario web_path_scan
    python -m attacker.run --target 127.0.0.1 --scenario all --loop

This is a **test client**, and it is important to be precise about what that
means. It connects *only* to a host and ports you name on the command line, at a
rate you set, and every scenario file it can run is version-controlled in this
repository. Its purpose is to prove the sensor records what it should — that the
telnet service tags Mirai credentials, that the HTTP parser flags Log4Shell,
that a burst trips the brute-force rule — against your own honeypot on your own
network.

It is deliberately not a scanner. There is no host discovery, no port sweeping,
no target list, no exploit that does anything to the far end beyond what a
honeypot is built to absorb. Point it at something that is not your honeypot and
it will simply hammer a closed port. Don't: sending this traffic to a host you
do not operate is unauthorised, whatever the payloads look like.

Scenarios are YAML; see ``attacker/scenarios/`` and the schema in
``load_scenario``.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import random
import sys
import time
from pathlib import Path
from typing import Any, Optional

import yaml

log = logging.getLogger("attacker")

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"

DEFAULT_PORTS = {"ssh": 2222, "telnet": 2323, "ftp": 2121, "http": 8081}


# --------------------------------------------------------------------------- #
# Scenario model
# --------------------------------------------------------------------------- #


class Scenario:
    """A parsed scenario file.

    Schema::

        name: web_path_scan
        service: http            # ssh | telnet | ftp | http
        description: ...
        rate_per_second: 20      # optional client-side throttle
        # service-specific payload lists:
        paths: [...]             # http
        usernames / passwords    # ssh, telnet, ftp
        credentials: [[u, p]]    # explicit pairs (telnet IoT lists)
        commands: [...]          # telnet/ssh post-login
        payloads: [...]          # http attack strings
        headers: {...}           # http
        user_agent: ...          # http
        count: 40                # how many actions
    """

    def __init__(self, data: dict[str, Any], source: str) -> None:
        self.source = source
        self.name: str = data.get("name", Path(source).stem)
        self.service: str = data["service"]
        self.description: str = data.get("description", "")
        self.rate_per_second: float = float(data.get("rate_per_second", 10))
        self.count: int = int(data.get("count", 20))
        self.data = data

        if self.service not in DEFAULT_PORTS:
            raise ValueError(f"scenario {self.name}: unknown service {self.service!r}")

    def get(self, key: str, default: Any = None) -> Any:
        return self.data.get(key, default)


def load_scenario(name_or_path: str) -> Scenario:
    path = Path(name_or_path)
    if not path.exists():
        path = SCENARIO_DIR / f"{name_or_path}.yaml"
    if not path.exists():
        raise FileNotFoundError(
            f"no scenario {name_or_path!r}; available: {', '.join(available_scenarios())}"
        )
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Scenario(data, source=str(path))


def available_scenarios() -> list[str]:
    return sorted(p.stem for p in SCENARIO_DIR.glob("*.yaml"))


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #


class RateLimiter:
    """A simple client-side throttle so a scenario is a trickle, not a flood."""

    def __init__(self, per_second: float) -> None:
        self.min_interval = 1.0 / per_second if per_second > 0 else 0.0
        self._last = 0.0

    async def wait(self) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        gap = self.min_interval - (now - self._last)
        if gap > 0:
            await asyncio.sleep(gap)
        self._last = time.monotonic()


# --------------------------------------------------------------------------- #
# Per-service drivers
# --------------------------------------------------------------------------- #


class Stats:
    def __init__(self) -> None:
        self.actions = 0
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.errors = 0


async def _connect(host: str, port: int, timeout: float = 5.0):
    return await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)


async def run_http(scenario: Scenario, host: str, port: int, limiter: RateLimiter, stats: Stats) -> None:
    paths = list(scenario.get("paths", ["/"]))
    payloads = list(scenario.get("payloads", []))
    user_agent = scenario.get("user_agent", "attacker-harness/1.0")
    headers = scenario.get("headers", {})
    method = scenario.get("method", "GET")

    targets = payloads or paths
    for i in range(scenario.count):
        await limiter.wait()
        target = targets[i % len(targets)]
        try:
            reader, writer = await _connect(host, port)
            request = _build_http_request(method, target, host, user_agent, headers)
            writer.write(request.encode("utf-8", "replace"))
            await writer.drain()
            stats.bytes_sent += len(request)
            data = await asyncio.wait_for(reader.read(2048), timeout=5)
            stats.bytes_recv += len(data)
            writer.close()
            await writer.wait_closed()
            stats.actions += 1
        except (OSError, asyncio.TimeoutError) as exc:
            stats.errors += 1
            log.debug("http action failed: %s", exc)


def _build_http_request(
    method: str, target: str, host: str, user_agent: str, headers: dict[str, str]
) -> str:
    lines = [f"{method} {target} HTTP/1.1", f"Host: {host}", f"User-Agent: {user_agent}"]
    for key, value in headers.items():
        lines.append(f"{key}: {value}")
    lines += ["Connection: close", "", ""]
    return "\r\n".join(lines)


async def run_telnet(scenario: Scenario, host: str, port: int, limiter: RateLimiter, stats: Stats) -> None:
    credentials = scenario.get("credentials")
    if credentials is None:
        usernames = scenario.get("usernames", ["root"])
        passwords = scenario.get("passwords", ["admin"])
        credentials = [[u, p] for u in usernames for p in passwords]
    commands = scenario.get("commands", [])

    for i in range(min(scenario.count, len(credentials))):
        await limiter.wait()
        username, password = credentials[i]
        try:
            reader, writer = await _connect(host, port)
            await asyncio.wait_for(reader.read(512), timeout=5)  # greeting + login:
            writer.write(f"{username}\r\n".encode())
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=5)  # Password:
            writer.write(f"{password}\r\n".encode())
            await writer.drain()
            response = await asyncio.wait_for(reader.read(2048), timeout=5)
            stats.actions += 1

            # If we got a shell (no "incorrect"), run the scripted commands.
            if commands and b"incorrect" not in response.lower():
                for command in commands:
                    await limiter.wait()
                    writer.write(f"{command}\r\n".encode())
                    await writer.drain()
                    await asyncio.wait_for(reader.read(2048), timeout=5)
                    stats.actions += 1
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            stats.errors += 1
            log.debug("telnet action failed: %s", exc)


async def run_ftp(scenario: Scenario, host: str, port: int, limiter: RateLimiter, stats: Stats) -> None:
    usernames = scenario.get("usernames", ["anonymous"])
    passwords = scenario.get("passwords", ["anonymous@"])
    pairs = [[u, p] for u in usernames for p in passwords][: scenario.count]

    for username, password in pairs:
        await limiter.wait()
        try:
            reader, writer = await _connect(host, port)
            await asyncio.wait_for(reader.read(512), timeout=5)  # banner
            for command in (f"USER {username}", f"PASS {password}", "SYST", "QUIT"):
                writer.write(f"{command}\r\n".encode())
                await writer.drain()
                await asyncio.wait_for(reader.read(512), timeout=5)
            stats.actions += 1
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            stats.errors += 1
            log.debug("ftp action failed: %s", exc)


async def run_ssh(scenario: Scenario, host: str, port: int, limiter: RateLimiter, stats: Stats) -> None:
    """Send the SSH version banner and a KEXINIT so the sensor can fingerprint us.

    We do not implement the full handshake — that needs a crypto library the
    harness intentionally avoids. Fingerprint mode is what most real scanners
    trigger anyway.
    """
    banner = scenario.get("client_banner", "SSH-2.0-libssh2_1.10.0")
    for _ in range(scenario.count):
        await limiter.wait()
        try:
            reader, writer = await _connect(host, port)
            await asyncio.wait_for(reader.read(256), timeout=5)  # server banner
            writer.write(f"{banner}\r\n".encode())
            await writer.drain()
            writer.write(_fake_kexinit())
            await writer.drain()
            await asyncio.wait_for(reader.read(512), timeout=5)
            stats.actions += 1
            writer.close()
            await writer.wait_closed()
        except (OSError, asyncio.TimeoutError) as exc:
            stats.errors += 1
            log.debug("ssh action failed: %s", exc)


def _fake_kexinit() -> bytes:
    """A minimal but well-formed SSH_MSG_KEXINIT for fingerprint testing."""
    import struct

    algorithms = [
        b"curve25519-sha256,ecdh-sha2-nistp256",
        b"ssh-ed25519,rsa-sha2-512",
        b"aes128-ctr,aes256-ctr",
        b"aes128-ctr,aes256-ctr",
        b"hmac-sha2-256,hmac-sha1",
        b"hmac-sha2-256,hmac-sha1",
        b"none", b"none", b"", b"",
    ]
    payload = bytes([20]) + b"\x00" * 16  # msg type + cookie
    for entry in algorithms:
        payload += struct.pack(">I", len(entry)) + entry
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_packet_follows + reserved

    padding_len = 8 - ((len(payload) + 5) % 8)
    if padding_len < 4:
        padding_len += 8
    packet = struct.pack(">I", len(payload) + padding_len + 1)
    packet += bytes([padding_len]) + payload + b"\x00" * padding_len
    return packet


DRIVERS = {"http": run_http, "telnet": run_telnet, "ftp": run_ftp, "ssh": run_ssh}


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


async def run_scenario(scenario: Scenario, host: str, port: Optional[int]) -> Stats:
    resolved_port = port or DEFAULT_PORTS[scenario.service]
    limiter = RateLimiter(scenario.rate_per_second)
    stats = Stats()

    log.info(
        "running %r against %s:%d (%s, %d actions, %.0f/s)",
        scenario.name, host, resolved_port, scenario.service,
        scenario.count, scenario.rate_per_second,
    )
    driver = DRIVERS[scenario.service]
    started = time.monotonic()
    await driver(scenario, host, resolved_port, limiter, stats)
    elapsed = time.monotonic() - started

    log.info(
        "  %r done: %d actions, %d errors, %.1fs (%.1f/s)",
        scenario.name, stats.actions, stats.errors, elapsed,
        stats.actions / elapsed if elapsed else 0,
    )
    return stats


def _refuses_target(host: str) -> Optional[str]:
    """Return a refusal reason if the target looks like it is not yours.

    A guardrail, not a security control: it only blocks the obvious mistake of
    pointing the harness at a public address, and can be overridden with
    ``--i-operate-this-target``. The real safeguard is the operator.
    """
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return None  # a hostname; can't classify, allow with the warning
    if addr.is_loopback or addr.is_private or addr.is_link_local:
        return None
    return (
        f"{host} is a public address. This harness is for testing a honeypot you "
        "operate, typically on localhost or a private network. If you really do "
        "operate this target, pass --i-operate-this-target to proceed."
    )


async def async_main(args: argparse.Namespace) -> int:
    if args.scenario == "all":
        names = available_scenarios()
    else:
        names = [args.scenario]

    scenarios = [load_scenario(name) for name in names]

    while True:
        for scenario in scenarios:
            await run_scenario(scenario, args.target, args.port)
        if not args.loop:
            break
        await asyncio.sleep(args.loop_delay)

    return 0


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Honeypot traffic generator (test client)")
    parser.add_argument("--target", default="127.0.0.1", help="honeypot host (default localhost)")
    parser.add_argument("--port", type=int, help="override the service's default port")
    parser.add_argument(
        "--scenario", default="all",
        help="scenario name, path, or 'all' (available: " + ", ".join(available_scenarios()) + ")",
    )
    parser.add_argument("--loop", action="store_true", help="repeat until interrupted")
    parser.add_argument("--loop-delay", type=float, default=10.0, help="seconds between loops")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument(
        "--i-operate-this-target", action="store_true",
        help="acknowledge you operate a non-private target (see README)",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)-7s %(message)s")

    if args.list:
        print("available scenarios:")
        for name in available_scenarios():
            try:
                scenario = load_scenario(name)
                print(f"  {name:<22} [{scenario.service}] {scenario.description}")
            except Exception as exc:  # pragma: no cover
                print(f"  {name:<22} (failed to load: {exc})")
        return 0

    refusal = _refuses_target(args.target)
    if refusal and not args.i_operate_this_target:
        print(f"refusing to run: {refusal}", file=sys.stderr)
        return 2

    try:
        return asyncio.run(async_main(args))
    except KeyboardInterrupt:
        return 0
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
