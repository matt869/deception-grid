# Architecture

This document explains how the system is put together and, more usefully, *why*
each piece is shaped the way it is. The code has the details; this has the
reasoning.

## The shape of the problem

A honeypot has an unusual constraint profile that drives almost every decision:

1. **Every byte in is hostile.** The input is chosen by an adversary who may be
   trying to crash the sensor, exhaust its disk, make it attack someone else, or
   simply detect that it is a honeypot and leave.
2. **The data is irreplaceable.** An observation missed is gone; you cannot ask
   the attacker to try again. This raises the cost of any bug that drops events.
3. **The sensor is a liability if it misbehaves.** An unbounded honeypot is a
   free amplifier; one that executes input is a compromised host; one that
   fetches attacker URLs is a proxy. "Do no harm" is a functional requirement.
4. **The output must be trustworthy.** An analyst will make attribution and
   blocking decisions from this data. Fabricated or mislabelled data is worse
   than missing data.

Every "why" below traces back to one of these four.

## Data flow

```
   TCP conn ─▶ asyncio listener ─▶ service emulator ─▶ HoneypotSession.record()
                                                              │
                                                     EventLogger.emit()  (non-blocking)
                                                              │  bounded queue
                                                     background writer thread
                                                              │  batched
                                          inline enrichment ──┤
                                                              ▼
                                                     SQLite / PostgreSQL
                                                              │
                        ┌─────────────────────────────────────┼───────────────────┐
                   detection (rules)                      API (FastAPI)        reporting
                   scoring (attackers)                         │              (digest/export)
                                                          dashboard (React)
```

## Component decisions

### The sensor (`honeypot/`)

**asyncio, one task per connection.** Honeypots are almost entirely I/O-bound —
thousands of slow, mostly-idle sockets. A thread per connection wastes memory at
that count; asyncio handles it in one process with predictable resource use.

**A shared deception layer, not per-service fakery.** All four services pull
their banners, prompts and command output from one `Persona` object
(`deception/banners.py`). Consistency is the entire game: an SSH banner claiming
Debian while HTTP says CentOS is an instant tell to anyone paying attention —
and the attackers worth studying are exactly the ones paying attention.

**The fake shell never executes anything** (`deception/responses.py`). It is a
dispatch table of pure functions returning canned output. There is no
`subprocess`, no `eval`, no filesystem write outside the payload directory.
`wget`/`curl` record the requested URL and return a plausible failure transcript
— the URL is captured intelligence (constraint 3), never fetched.

**The event writer is non-blocking by construction** (`logger.py`). The asyncio
loop must never block on disk or DB I/O — a slow fsync while holding the loop
stalls every live connection and changes the sensor's timing fingerprint. So
`emit()` puts a dict on a **bounded** queue and returns; one background thread
drains it in batches. The queue is bounded on purpose: if a flood outruns the
writer, dropping and *counting* the overflow (constraint 3) beats growing until
the process is OOM-killed and the sensor goes dark. Dropped counts surface in
the stats line, so loss is never silent.

**Budgets everywhere** (`session.py`, `config.py`). Per-session byte and event
caps, global and per-IP connection limits, line-length limits, read timeouts.
These exist to protect the sensor (constraint 3), and the per-IP cap matters as
much as the global one — one noisy source must not starve every other
observation.

**SSH has two modes** (`services/ssh_service.py`). Without `paramiko`, it does
the RFC 4253 version exchange and derives a **HASSH** fingerprint from the
client's `KEXINIT` — which identifies the *tool* even when the banner is forged,
and needs no crypto dependency. With `paramiko`, it completes the handshake and
captures passwords. Fingerprint mode is the default so the sensor has no hard
crypto dependency and always starts (a sensor that fails to start collects
nothing).

### Storage (`storage/`)

**Denormalised in two deliberate places.** `Event` carries a flattened copy of
its enrichment (country, ASN, score) because events are written once and read
constantly — paying the storage cost beats joining three tables on every
dashboard query. `Attacker` is a *rebuildable* aggregate over events,
never the source of truth: dropping it and re-running `rebuild_attackers()` is
always safe, which keeps the sensor's hot path a single INSERT.

**SQLite is tuned, not just used** (`db.py`). WAL mode + a busy timeout, because
the sensor writes continuously while the API reads, and the default journal mode
makes them block each other — it shows up as `database is locked` under light
load. The same code runs on PostgreSQL unchanged for production.

**Timestamps are normalised on every read** (`ensure_utc`). SQLite has no
timestamp type and hands back naive datetimes even for tz-aware columns;
comparing one to `utcnow()` raises. Every read path funnels through `ensure_utc`.

### Enrichment (`pipeline/enrichment/`)

**Offline-first, and it never calls out.** Every lookup reads a local `.mmdb`, a
local prefix table, or local indicator files. This is constraint 3 again: a
lookup that phones a third party on every observed IP leaks your sensor's view
to that third party and hands anyone watching your egress a real-time feed of
what you're seeing.

**Missing data must look missing** (constraint 4). If there's no GeoLite2
database, a public IP returns `country: null` with `geo_source: "unavailable"`
— never a guess. An analyst who attributes an intrusion to the wrong country
because the dashboard invented one is worse off than one who sees a blank.

**Synthetic data is indelibly labelled.** The demo generators stamp
`geo_source: "synthetic"` and use private-use ASN numbers, so generated data can
never be confused with a measurement (constraint 4).

**The "mozi in mozilla" guard.** User-agent matching is word-boundary aware
because a substring test flags every `Mozilla` browser as the Mozi botnet — a
false "malware" verdict on routine traffic poisons the score, the class and any
exported blocklist. That check has a regression test.

### Detection (`pipeline/detection/`)

**Rules are data, not code** (`rules.yaml`). Adding a detection is a reviewable
YAML change, readable by someone who doesn't read Python. The engine validates
strictly and loads fail-loud: a detection that silently fails to load is worse
than one that refuses to start.

**Sliding-window evaluation.** A rule's window slides over the *events
themselves*, not "the last N minutes before now." This is the only semantics
correct in both directions: anchoring to wall-clock now means replaying
yesterday's data detects nothing and a slightly-late scheduled run misses its
burst. Sliding makes detection a reproducible property of the data — the same
events always yield the same alerts, which also makes it testable without a
clock.

**Deduplication by design.** One alert per `(rule, group)` with a hit counter,
not one per matching event. `hit_count` takes the max on re-evaluation (the
incoming value is a recomputed peak, so summing would double-count every
scheduled re-run). The result is an idempotent detection pass and a triage queue
an analyst can actually read.

**Scoring is transparent, not learned** (`scoring.py`). A bounded additive model
where every component is documented and independently inspectable, so an analyst
can always answer "why is this IP an 82?" A black-box classifier that scores
better on average but can't justify a single verdict is the wrong trade for
triage, where the output has to survive being questioned. The weights encode one
opinion: *what* an attacker did outweighs *how much* — one shell command beats
ten thousand connection attempts.

### API (`api/`)

**Read-mostly, with schemas separate from the ORM.** Pydantic response models
are defined apart from the SQLAlchemy models so the API surface doesn't leak
internal columns and a schema change isn't automatically a breaking API change.
Password exposure is a policy decision made at this boundary
(`API_REDACT_PASSWORDS`).

**No auth, and a guardrail that says so.** The API expects a private network or
an authenticating proxy. It refuses to start with a wildcard CORS origin unless
`API_ALLOW_INSECURE=1`, turning the one silently-dangerous configuration into a
deliberate act.

### Dashboard (`dashboard/`)

**Hand-rolled SVG charts against a validated palette.** The service colours
passed a colourblind-safety validation; colour follows the *service* in fixed
order, never its stack position, so a filter that changes which services are
present never repaints the survivors. Charts carry one y-axis, direct legends
and hover tooltips. The attacker profile leads with the score *breakdown*
because the explanation is the product.

**Incremental live feed.** The feed polls with an `after_id` cursor so each poll
transfers only what arrived since the last, and pauses when the tab is hidden.

## Failure modes and how they're contained

| If this happens… | …the system does this |
|---|---|
| Malformed packet crashes a handler | `base.py` catches it, records an `error` event, closes that one socket; the listener survives |
| Event flood outruns the writer | bounded queue drops overflow and counts it; sensor stays up |
| One detection rule throws | `evaluate_rules` isolates it; the other rules still run |
| Enrichment dependency missing | lazily imported; feature disabled, sensor unaffected |
| GeoIP database absent | lookups return `unavailable`; nothing is guessed |
| Attacker aggregate corrupted | drop it, `rebuild_attackers()` from raw events |
| SQLite reader/writer contention | WAL + busy timeout |

## Testing

`tests/unit` covers the pure parse-and-classify code and the rule/scoring logic
without a database — a detection rule is a claim about a shape of behaviour, and
the tests state that shape directly. `tests/integration` starts a **real**
asyncio listener, drives it with a real TCP client, and asserts the interaction
lands in the database correctly tagged — the only place the socket plumbing,
writer thread and enrichment hook are exercised together — then drives the full
FastAPI surface against a temp database.
