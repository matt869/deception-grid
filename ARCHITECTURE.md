# Architecture & how it works

This document explains how the system is put together and, more usefully, *why*
each piece is shaped the way it is. It reflects the **deployed** system — six
bait services, an offline-first enrichment/detection pipeline, real-time
alerting, threat-intel feeds, geolocation, IOC export, and the hardened Azure
topology. The code has the details; this has the reasoning and the end-to-end
walkthrough.

---

## 1. The shape of the problem

A honeypot has an unusual constraint profile that drives almost every decision:

1. **Every byte in is hostile.** The input is chosen by an adversary who may be
   trying to crash the sensor, exhaust its disk, make it attack someone else, or
   simply detect that it is a honeypot and leave.
2. **The data is irreplaceable.** An observation missed is gone; you cannot ask
   the attacker to try again. This raises the cost of any bug that drops events.
3. **The sensor is a liability if it misbehaves.** An unbounded honeypot is a
   free amplifier; one that executes input is a compromised host; one that
   fetches attacker URLs is a proxy. "Do no harm" is a functional requirement.
4. **The output must be trustworthy.** An analyst makes attribution and blocking
   decisions from this data. Fabricated or mislabelled data is worse than
   missing data.

Every "why" below traces back to one of these four.

---

## 2. System topology (as deployed)

The production deployment is four Docker containers on one VM. The attacker only
ever reaches the **sensor**; the analyst only ever reaches the **dashboard**, and
only through an SSH tunnel.

```
   internet (attackers)                          you (analyst)
        │  22/23/80/21/6379/3306                     │  ssh -L 8080 (port 62222)
        ▼                                            ▼
┌──────────────────────────┐                 ┌───────────────────────────┐
│  sensor  (honeypot/)      │                 │  dashboard  (nginx+React) │
│  6 asyncio listeners      │                 │  bound 127.0.0.1:8080     │
│  deception layer          │                 │  proxies /api ─────────┐  │
│  inline enrichment ──┐    │                 └────────────────────────┼──┘
│  batched writer      │    │                                          │
└──────────┬───────────┘    │   mounts (read-only):                    │
           │ INSERT         │     ./data/geolite2  (DB-IP / GeoLite2)   │
           ▼                │     ./data/indicators (threat-intel feeds)│
   ┌───────────────┐        │   volume: sensor_data (payloads, host key)│
   │ db (Postgres) │◀───────┼──────────────────────────────────────────┤
   └───────┬───────┘   read │                                          │
           │                ▼                                          │
           │        ┌──────────────────────────┐                      │
           └───────▶│  api  (FastAPI)           │◀─────────────────────┘
                    │  bound to compose net only│   (nginx → api:8000)
                    │  detection + scoring       │
                    │  IOC export                │
                    │  Discord/webhook alerting ─┼──▶  Discord
                    └──────────────────────────┘
                              ▲
        host cron ────────────┘  every 5 min: run detection + rebuild scores
        host cron:  hourly IOC export · nightly pg_dump · weekly prune + feed refresh
        fail2ban:   guards admin SSH on 62222 (behind the NSG)
```

Two properties are structural, not incidental:

- **The API is never published to the host.** nginx inside the dashboard
  container reaches it over the compose network (`api:8000`). So even though the
  API has no authentication, it is unreachable from the internet — the only way
  in is the tunnel to the localhost-bound dashboard.
- **The scheduler is host cron hitting the API**, not a process inside a
  container. Detection, scoring, export, backups, retention and feed refresh are
  ordinary cron jobs calling `/api/...` or `docker compose exec`. This keeps the
  containers stateless and the schedule visible in `crontab -l`.

---

## 3. Life of an event (end to end)

The single most useful thing to understand is what happens from a packet
arriving to an alert reaching Discord:

1. **Connect.** An attacker opens a TCP connection to, say, port 23. Docker
   forwards host `23 → container 2323`; the sensor's `TelnetService` accepts it.
   `SessionRegistry` enforces admission control (global + per-IP concurrency);
   over budget, the socket is closed silently (a visible rate-limiter is itself a
   fingerprint).

2. **Converse.** The service emulates the protocol from the shared `Persona`
   (consistent banners/prompts across all services). Telnet strips IAC control
   bytes, captures credentials, and — on a "successful" login — hands the
   attacker a `FakeShell` that **executes nothing**; it is a dispatch table of
   pure functions. A `wget` records the URL as intelligence and returns a
   plausible failure. Each meaningful action becomes an event via
   `HoneypotSession.record()`, tagged (`iot-default-credential`,
   `mirai-signature`, `payload-fetch`, …).

3. **Emit (non-blocking).** `record()` calls `EventLogger.emit()`, which puts a
   dict on a **bounded queue** and returns immediately. The asyncio loop never
   touches disk or the database, so one slow write can't stall the other live
   connections or change the sensor's timing fingerprint.

4. **Enrich + write (background thread).** A single writer thread drains the
   queue in batches. For each event it runs **inline enrichment** — geolocation
   (DB-IP/GeoLite2 `.mmdb`), ASN/operator, and threat-intel matching against the
   loaded feeds — flattening the results onto the event, then writes the batch to
   PostgreSQL. If a flood outruns the writer, overflow is dropped **and counted**
   (constraint 3), never buffered without bound.

5. **Detect (every 5 min).** A host cron POSTs `/api/alerts/run`. The engine
   loads the recent events, evaluates all 24 YAML rules over a **sliding window
   of the events themselves**, and upserts alerts deduplicated by
   `(rule, group)`. It returns the set of *newly created* alerts.

6. **Score (every 5 min).** A host cron POSTs `/api/attackers/rebuild`, which
   recomputes each source's 0–100 threat score and behavioural class from its
   raw events using a transparent additive model.

7. **Alert (immediately after detection).** For each *newly created* alert at or
   above `ALERT_MIN_SEVERITY`, the notifier POSTs a message to the Discord
   webhook — severity-gated, rate-capped, and best-effort so a webhook outage
   can't break detection.

8. **Observe / act.** The analyst opens the dashboard through the tunnel and
   sees it all; hourly, another cron writes a deployable blocklist and STIX
   bundle to `exports/` via the same `/api/export/*` endpoints.

---

## 4. Component deep-dives

### 4.1 The sensor (`honeypot/`)

**asyncio, one task per connection.** Honeypots are almost entirely I/O-bound —
thousands of slow, mostly-idle sockets. A thread per connection wastes memory at
that count; asyncio handles it in one process with predictable resource use.
`services/base.py` provides admission control, timeouts, byte accounting and —
critically — **error containment**: any exception from a service handler is
caught, recorded as an `error` event, and closes only that socket. One malformed
packet never takes down a listener.

**Six emulated services**, all subclasses of `BaseService`:

| Service | Port (host→container) | What it captures |
|---|---|---|
| SSH | 22→2222 | HASSH fingerprint + banner (always); passwords + shell (with paramiko) |
| Telnet | 23→2323 | IoT default creds (Mirai list), full loader command sequence |
| FTP | 21→2121 | credential sprays; refuses `PORT` (bounce) and uploads |
| HTTP | 80→8081 | Log4Shell, Shellshock, SQLi, traversal, webshell, secret-file probes |
| **Redis** | 6379→6379 | the unauth-RCE chain: `CONFIG SET`, `SLAVEOF`, `MODULE`, SSH-key/cron `SET` |
| **MySQL** | 3306→3306 | login usernames from the handshake (minimal binary protocol) |

**A shared deception layer, not per-service fakery.** All services pull banners,
prompts and command output from one `Persona` object (`deception/banners.py`).
Consistency is the entire game: an SSH banner claiming Ubuntu while HTTP says
CentOS is an instant tell, and the attackers worth studying are the ones paying
attention.

**The fake shell never executes anything** (`deception/responses.py`) — no
`subprocess`, no `eval`, no filesystem write outside the payload directory. Redis
`SET`/`CONFIG`, MySQL logins, `wget`/`curl` are all lookups or recordings.
Attacker-supplied URLs are captured intelligence (constraint 3), never fetched.

**The event writer is non-blocking by construction** (`logger.py`). `emit()`
enqueues and returns; one background thread batches to disk/DB and runs inline
enrichment. The queue is **bounded on purpose**: overflow is dropped and counted
rather than growing until an OOM kill takes the sensor dark. Captured payloads
are stored by content hash (dedup) in the `sensor_data` volume.

**Budgets everywhere** (`session.py`, `config.py`): per-session byte and event
caps, global and per-IP connection limits, line-length limits, read timeouts.
The per-IP cap matters as much as the global one — one noisy source must not
starve every other observation.

**SSH has two modes** (`services/ssh_service.py`). Without `paramiko`: the RFC
4253 version exchange plus a **HASSH** fingerprint derived from the client's
`KEXINIT`, which identifies the *tool* even when the banner is forged. With
`paramiko` (the deployed image): the full handshake, capturing passwords and
public-key attempts. Fingerprint mode is the default so the sensor has no hard
crypto dependency and always starts.

### 4.2 Storage (`storage/`)

**Denormalised in two deliberate places.** `Event` carries a flattened copy of
its enrichment (country, ASN, score) because events are write-once,
read-constantly — cheaper than joining three tables per dashboard query.
`Attacker` is a *rebuildable* aggregate, never the source of truth: dropping it
and re-running `rebuild_attackers()` is always safe, keeping the sensor's hot
path a single INSERT. Tables: `events`, `sessions`, `attackers`, `alerts`,
`indicators`.

**Engine-agnostic.** SQLite (dev) is tuned with WAL + a busy timeout so the
continuous writer and the API's reads don't deadlock; PostgreSQL (production)
runs the same code unchanged. **`ensure_utc` on every read** normalises the naive
datetimes SQLite hands back, so comparisons against `utcnow()` never raise.

### 4.3 Enrichment (`pipeline/enrichment/`)

**Offline-first, and it never calls out.** Every lookup reads a local `.mmdb`, a
local prefix table, or local indicator files. A lookup that phoned a third party
on every observed IP would leak the sensor's view and hand anyone watching egress
a real-time feed of what it sees (constraint 3). The one network-touching action,
`tools/refresh_indicators.py`, is explicit and operator-run, never part of
enrichment.

- **Geolocation** (`geoip.py`) reads a City `.mmdb`. It recognises MaxMind
  GeoLite2 **and** the free, no-license-key **DB-IP Lite** (`dbip-city-lite-*.mmdb`)
  by glob — same MMDB format. Absent a database, it returns `country: null` with
  `geo_source: "unavailable"`; **it never guesses** (constraint 4).
- **ASN/operator** (`asn.py`) reads a `GeoLite2-ASN`/`dbip-asn-lite-*` `.mmdb`, or
  falls back to a local prefix table with longest-prefix match. Operator strings
  are classified (`hosting-provider`, `vpn-or-tor`, `consumer-isp`) offline.
- **Threat intel** (`threat_intel.py`) matches the source IP against **159k+
  indicators** loaded from `data/indicators/*.txt` (blocklist.de, ipsum, FireHOL)
  and the `indicators` table, plus built-in user-agent/username heuristics. The
  **"mozi in mozilla" guard** makes UA matching word-boundary aware so a browser
  is never mislabelled as the Mozi botnet — with a regression test.

**Synthetic data is indelibly labelled** (`geo_source: "synthetic"`, private-use
ASNs) so demo data can never be mistaken for a measurement.

### 4.4 Detection (`pipeline/detection/rules.py`, `rules.yaml`)

**Rules are data, not code** — a reviewable YAML change, validated fail-loud on
load. 24 rules across credential attacks, post-exploitation, web exploits,
datastore abuse (Redis/MySQL) and behaviour.

**Sliding-window evaluation.** A rule's window slides over the *events
themselves*, not "the last N minutes before now." This is the only semantics
correct in both directions: anchoring to wall-clock now means replaying old data
detects nothing and a slightly-late scheduled run misses its burst. Sliding makes
detection a reproducible property of the data.

**Deduplication by design.** One alert per `(rule, group)` with a hit counter;
`hit_count` takes the **max** on re-evaluation (the incoming value is a recomputed
peak, so summing would double-count every scheduled run). The pass is idempotent
and the triage queue is readable. `persist_alerts` returns the newly-created
alerts so the notifier pages on those alone.

### 4.5 Scoring (`pipeline/detection/scoring.py`)

**Transparent additive model, not learned.** Seven bounded, documented components
(post-exploitation, severity, threat-intel, credential breadth, volume,
persistence, service breadth) sum and clamp to 0–100, then decay with recency
(floored at 40%). An analyst can always answer "why is this IP an 82?" from
`score_breakdown`. The weights encode one opinion: *what* an attacker did
outweighs *how much* — one shell command beats ten thousand connects. A
behavioural class (`botnet-loader`, `targeted-intrusion`, `web-scanner`, …) is
assigned by ordered rules, most-specific first.

### 4.6 Real-time alerting (`pipeline/alerting/`)

**Push, not poll.** When detection creates a *new* alert at/above the threshold,
the notifier POSTs to a Slack/Discord/Teams/generic webhook (auto-detected from
the URL). Three properties keep it usable: **new-only** (idempotent runs don't
re-page), **severity-gated** (`ALERT_MIN_SEVERITY`, default high), and
**rate-capped** (`ALERT_MAX_PER_RUN` messages + one "+N more" summary). It is
stdlib-only (`urllib`) so it adds nothing to the image, and best-effort so a
webhook outage never breaks the pipeline.

### 4.7 API (`api/`) and reporting/export

**Read-mostly, schemas separate from the ORM**, so the surface doesn't leak
internal columns and a schema change isn't automatically breaking. Password
exposure is a boundary policy (`API_REDACT_PASSWORDS`). **No auth, and a
guardrail that says so**: the app refuses to start with a wildcard CORS origin
unless `API_ALLOW_INSECURE=1`. A handful of write endpoints exist for triage
(`PATCH /alerts`), on-demand detection/rebuild (used by cron), and **IOC export**
(`/api/export/{blocklist,stix,misp,events.csv,alerts.csv}`), which apply a score
floor so a blocklist isn't mostly researchers and NAT gateways.

### 4.8 Dashboard (`dashboard/`)

**Hand-rolled SVG charts against a colourblind-validated palette.** Colour follows
the *service* in fixed order (six now, incl. Redis/MySQL), never its stack
position, so a filter never repaints the survivors. One y-axis, direct legends,
hover tooltips; the attacker profile leads with the score *breakdown* because the
explanation is the product. The **live feed** polls with an `after_id` cursor
(only new rows) and pauses when the tab is hidden. Served by nginx, bound to
localhost, reached via SSH tunnel.

---

## 5. Deployment architecture

- **Port strategy.** Bait runs on the real low ports (22/23/80/21/6379/3306) via
  Docker's `low:high` publish; admin SSH is relocated to **62222** so the
  honeypot can own 22. The dashboard publishes to `127.0.0.1:8080` only; the API
  publishes nothing.
- **Compose + override.** The committed `docker-compose.yml` is generic; a
  `docker-compose.override.yml` on the VM rebinds the bait to low ports, mounts
  the geo/indicator databases read-only and the `sensor_data` volume, passes the
  alerting env, and locks the dashboard to localhost.
- **NSG.** Admin `62222` is Source-restricted to the operator's IP; the bait
  ports are open to `Any`; the dashboard/API are not in the NSG at all.
- **Scheduling (host cron).** detection + rebuild every 5 min; IOC export hourly;
  `pg_dump` nightly (7-day rotation); event pruning + feed refresh weekly.
- **Hardening.** `fail2ban` on the admin port (behind the NSG), Docker
  log-rotation (scanners are relentless), non-root container users, and payloads
  isolated in a named volume.
- **Geo without a license key.** DB-IP Lite (City + ASN) is downloaded with no
  account, dropped into `data/geolite2/`, and recognised automatically. MaxMind
  GeoLite2 works too if you have a key.

See [docs/deployment-azure.md](docs/deployment-azure.md) for the exact runbook and
[docs/live-evidence.md](docs/live-evidence.md) for measured proof it works.

---

## 6. Failure modes and how they're contained

| If this happens… | …the system does this |
|---|---|
| Malformed packet crashes a handler | `base.py` records an `error` event, closes that one socket; the listener survives |
| Event flood outruns the writer | bounded queue drops overflow and counts it; sensor stays up |
| One detection rule throws | `evaluate_rules` isolates it; the other rules still run |
| Enrichment dependency missing | lazily imported; feature disabled, sensor unaffected |
| Geo/ASN database absent | lookups return `unavailable`; nothing is guessed |
| Webhook down / alert send fails | logged and counted; detection is never blocked |
| Attacker aggregate corrupted | drop it, `rebuild_attackers()` from raw events |
| API container recreated (new IP) | restart `dashboard` so nginx re-resolves the upstream |
| PostgreSQL driver missing | image build fails loudly (psycopg2 pinned in the Dockerfiles) |
| DB reader/writer contention (SQLite) | WAL + busy timeout |

---

## 7. Testing

`tests/unit` covers the pure parse-and-classify code and the rule/scoring/alerting
logic without a database — a detection rule is a claim about a shape of behaviour,
and the tests state that shape directly (the notifier's `_send` is stubbed so
delivery logic is asserted without network). `tests/integration` starts a **real**
asyncio listener, drives it with a real TCP client, asserts the interaction lands
in the database correctly tagged — the only place the socket plumbing, writer
thread and enrichment hook run together — then drives the full FastAPI surface
against a temp database. CI runs lint + format + the suite on 3.11/3.12, an
end-to-end seed→detect→API smoke, and the dashboard build.

---

## 8. Security posture (the "do no harm" summary)

- **Executes nothing** an attacker sends; the shell and all services are
  emulators.
- **Reaches out to nobody** during enrichment or capture; attacker URLs are
  recorded, never fetched; feed/geo refresh is explicit and operator-run.
- **Bounded** on every axis (connections, bytes, events, queue) so it can't be
  turned into an amplifier or a disk-filler.
- **Honest output**: missing data reads as missing; synthetic data is labelled;
  scores are explainable.
- **Contained blast radius**: admin plane on a restricted high port, dashboard on
  localhost, API unpublished, captured malware isolated in a volume and never run.
