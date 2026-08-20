# Benchmarks

```
python -m tools.benchmark                      # everything, default sizes
python -m tools.benchmark --only query
python -m tools.benchmark --events 100000 --json results.json
```

Every run builds a throwaway SQLite database in a temp directory and points
`DATABASE_URL` at it for the duration. It never touches a live sensor's store —
seeding tens of thousands of synthetic events into a real capture would be
unrecoverable, because synthetic rows are indistinguishable from real ones after
the fact. There is a test asserting the isolation holds even when a benchmark
raises.

## What is measured

| Benchmark | Why it is here |
|---|---|
| `ingest` | `EventLogger.emit` through the queue and batching writer. The queue is bounded, so this is the number that decides whether a burst is captured or dropped. |
| `enrich` | Geo/ASN/threat-intel per event. Runs inside the writer thread, so it is a direct tax on ingest. |
| `detect` | One rule-evaluation pass. Runs on a timer, so what matters is finishing well inside the interval. |
| `query` | Dashboard endpoints, as latency percentiles — a p95 is what an analyst experiences. |
| `analyse` | Static payload analysis per artefact. |
| `rebuild` | Recomputing the attacker aggregate from raw events. |

Absolute numbers are machine-specific and worth little on their own. They are
useful as a before/after around a change, and as an early warning when
something moves by an order of magnitude.

## Reference run

Python 3.11, Windows, SQLite, 20k seeded events over a 24-hour window.

| benchmark | n | rate | p50 | p95 |
|---|---|---|---|---|
| ingest | 5,000 | 3,562 events/s | | |
| ingest+enrich | 5,000 | 2,569 events/s | | |
| enrich | 20,000 | 39,748 events/s | | |
| analyse | 500 | 921 artefacts/s | | |
| detect | 30,000 | 10,692 events/s | | |
| rebuild_attackers | 256 | 177 attackers/s | | |
| query:summary | 20 | | 30.2ms | 39.4ms |
| query:events | 20 | | 2.2ms | 3.4ms |
| query:attackers | 20 | | 1.4ms | 1.8ms |
| query:timeseries | 20 | | 37.4ms | 51.9ms |
| query:top_creds | 20 | | 14.9ms | 18.9ms |
| query:sessions | 20 | | 0.3ms | 0.5ms |

Enrichment costs roughly a quarter of ingest throughput (3,562 → 2,569
events/s), which is the trade the writer thread is making on your behalf.

## What the first run found

Two dashboard endpoints dominated everything else, and both are on the overview
page — the first thing anyone loads.

**`summary_stats` issued eight separate queries**, six of them full scans of the
same `events` rows for different counters. Folded into one pass with conditional
aggregation. Watch for `SUM` over zero rows returning `NULL` rather than `0`;
there is a test for the empty window.

**`events_timeseries` pulled every event in the window back into Python** to
bucket it there. The module docstring justified this as noise at dashboard
volumes. It was not: 162ms p50 over 20k events, growing linearly with the
window. Two fixes, in order of how embarrassing they are:

1. `_floor` constructed `datetime(1970, 1, 1)` on every call — once per event.
   Hoisting it to a module constant took 162ms → 103ms on its own.
2. Grouping moved into SQL, transferring one row per bucket per series instead
   of one row per event. Measured head-to-head against the Python path on
   identical data: **96.8ms → 21.5ms**.

| | before | after |
|---|---|---|
| `query:summary` | 67.3ms p50 | 30.2ms p50 |
| `query:timeseries` | 162.1ms p50 | 37.4ms p50 |
| `rebuild_attackers` | 177/s | 258/s |

**`rebuild_attackers` was an N+1**: two queries per attacker — a `SELECT` for
its events and a `get()` for its row — so 512 queries for 256 attackers. Now one
ordered pass grouped with `itertools.groupby`, two queries per batch, with
`yield_per` so a full rebuild is bounded by the largest single attacker rather
than by the whole events table. **177 → 258 attackers/s.**

That is a smaller win than the query fixes, and the profile says why: the
remaining time is inherent rather than wasted. Of ~1.7s, roughly 0.5s is
building 20k ORM `Event` objects and 0.5s is `score_attacker` itself.

An optimisation that did **not** work, recorded so nobody spends the afternoon
again: narrowing the load with `load_only()` to skip the unused JSON and text
columns measured *slower* than loading everything (474ms vs 461ms) — the
deferred-column machinery costs about what the skipped decoding saves. Selecting
plain column rows instead of ORM objects does help (244ms), but that is ~15% of
the total for a real semantic change, since `score_attacker` would then receive
`Row` objects instead of `Event`s. Left alone deliberately.

### The bug that fix nearly shipped with

The SQL grouping needs a bucket index, spelled `strftime('%s', …)` on SQLite and
`extract(epoch from …)` on PostgreSQL. The first version divided with Python's
`/`, and SQLAlchemy renders that as `x / (3600 + 0.0)` to force float semantics.
The index came back fractional — `496432.9555…` — so every row landed in its own
bucket. The query still returned, the chart still drew, and the endpoint was no
faster.

What caught it was not the benchmark being slow; it was checking the row count
and finding 20,000 groups where there should have been 125. The dialect branch
now carries a test asserting the SQL path and the Python path produce
**identical** output across every bucket size and dimension — the only kind of
test that makes two code paths for one chart safe.

## Adding a benchmark

Write a `bench_*` function returning a `Result`. Pass `samples=` for anything
latency-shaped so it reports percentiles instead of a rate, and add the name to
`BENCHMARKS`.
