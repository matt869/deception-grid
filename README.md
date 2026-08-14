# Honeypot Dashboard

A multi-service honeypot sensor, an offline-first enrichment and detection
pipeline, and an analyst dashboard — one system that watches for attackers,
records exactly what they do, and turns the raw capture into something you can
read.

It emulates SSH, Telnet, FTP and HTTP; keeps automated attackers engaged long
enough to observe their whole playbook; enriches every event with geolocation,
network ownership and local threat intel; scores and classifies each source with
a transparent model; raises deduplicated alerts from declarative rules; and
serves it all through a FastAPI backend and a React dashboard.

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
# SSH:2222  Telnet:2323  FTP:2121  HTTP:8081

# then, from another machine or terminal, exercise it with the test client:
python -m attacker.run --target 127.0.0.1 --scenario all
```

To take real internet traffic, map the low ports to the high ones at your
firewall (`22 → 2222`, etc.) — never run the sensor as root.

---

## Architecture

```
                          ┌─────────────────────────────────────────┐
   attackers ───tcp──▶    │  honeypot/  (asyncio, one task per conn) │
                          │  ssh · telnet · ftp · http               │
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
| [`honeypot/`](honeypot/) | The sensor. Async listeners for four protocols, a shared deception layer, and a non-blocking batched event writer. |
| [`pipeline/enrichment/`](pipeline/enrichment/) | GeoIP, ASN and local threat-intel. Offline-first: absent data looks absent, never guessed. |
| [`pipeline/detection/`](pipeline/detection/) | A declarative YAML rule engine ([`rules.yaml`](pipeline/detection/rules.yaml)) and a transparent additive scoring model. |
| [`pipeline/reporting/`](pipeline/reporting/) | Daily Markdown digests and export to CSV/JSONL/STIX/MISP/blocklist. |
| [`storage/`](storage/) | ORM models, engine management (WAL-tuned SQLite, or Postgres), and the analytics queries the API and reports share. |
| [`api/`](api/) | FastAPI read API plus a few triage endpoints. |
| [`dashboard/`](dashboard/) | React dashboard: overview, live feed, attacker profiles, alert triage. |
| [`attacker/`](attacker/) | A test client (not a scanner) that replays version-controlled scenarios against *your* honeypot. |
| [`tools/`](tools/) | Seed synthetic data, reset/prune the DB, import Cowrie / auth.log / JSONL. |

---

## What it detects

Detection is [21 declarative rules](pipeline/detection/rules.yaml) evaluated over
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
- **Behaviour** — multi-service sweeps, FTP bounce attempts, high-volume
  sources, threat-intel matches.

Each source gets a 0–100 threat score from a **transparent, inspectable** model
(volume, persistence, credential breadth, service breadth, severity,
post-exploitation, threat-intel — each bounded and weighted), plus a behavioural
class (`botnet-loader`, `targeted-intrusion`, `web-scanner`, …). The dashboard
shows the full breakdown for every attacker — see [docs/detection_rules.md](docs/detection_rules.md).

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
| `API_REDACT_PASSWORDS` | off | blank captured passwords in API responses |
| `API_CORS_ORIGINS` | localhost:5173 | dashboard origin(s) |

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
