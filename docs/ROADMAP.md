# Roadmap

Where Deception Grid is going, and why in this order. The organising principle:
**ship the thing that produces evidence, then build on the evidence.** A working
sensor with three weeks of real capture is worth more than six half-built
features, so nothing here is scheduled ahead of the data it depends on.

Status keys: **done** · **next** · **planned**

---

## Phase 0 — Foundation · done

The single-sensor system, deployed and taking real traffic.

| Capability | State |
|---|---|
| Seven emulated services (SSH, Telnet, FTP, HTTP, Redis, MySQL, Docker API) | done |
| Offline-first enrichment (GeoIP, ASN, local threat intel) | done |
| Declarative detection rules + transparent scoring | done |
| Session replay | done |
| Real-time alerting + daily chat digest | done |
| ATT&CK coverage reporting | done |
| Azure deployment runbook, evidence, screenshots | done |

---

## Phase 1 — Fleet · next

The upgrade that turns one instance into a platform. Everything after this is
optional; this is not.

**Goal:** many sensors, one backend, one dashboard.

| Piece | What it means | Why |
|---|---|---|
| Ingest API | Sensors POST events to the backend instead of writing to the database directly | Removes the assumption that sensor and database share a host |
| Sensor identity | Per-sensor key; every event authenticated and attributed | Without it, anyone who finds the ingest endpoint can poison the dataset |
| Fleet view | Sensor list: health, last-seen, event rate, version | A silent sensor is indistinguishable from a quiet internet until you can see it |
| Regional comparison | Same bait in different regions and clouds | Turns the project from "I ran a honeypot" into a question with an answer |

**Design note.** The sensor already writes through a queue and a batching writer,
so the ingest change is a new sink behind the same interface — not a rewrite.
Sensors must keep buffering locally when the backend is unreachable; a sensor
that drops captures because the collector restarted is worse than no fleet.

**Done when:** two sensors in different regions report to one dashboard, and the
evidence doc compares what each of them caught.

---

## Phase 2 — Depth

Ordered by value per hour of work.

### Payload analysis · engine done, surfacing next

**Done — `pipeline/analysis/static.py`.** File typing from magic bytes, ELF and
PE header parsing, embedded strings, defanged URL/IP/domain extraction, Shannon
entropy with a packing heuristic, behavioural tagging from the strings table,
and optional YARA when `yara-python` and rules are present. Runs standalone:

```
python -m pipeline.analysis.static --scan
python -m pipeline.analysis.static data/payloads/<sha256>.bin --json
```

Architecture is the field that earns its place. IoT botnets ship one build per
CPU family and the loader picks by `uname`, so `e_machine` records what the
operator thought this sensor was — and `mips / static / stripped` is a shape
the session transcript alone never shows.

**Still to do:** persistence and surfacing. A `payloads` table keyed by SHA256,
joined to the event that carried it, exposed on the attacker profile so a
loader's dropper sits next to the session that fetched it. The analyser is a
pure function over bytes today; nothing stores its output yet.

*Constraint that does not move: nothing is ever executed, and nothing is ever
fetched. Static analysis only. Every indicator the analyser returns is defanged
before it leaves the function, and there is a test that says so.*

### Campaign clustering · planned
Group sources by behavioural similarity — command sequences, credential sets,
timing, ASN — instead of by IP. Answers "is this the same operator from a new
address?", which is the question an IP-keyed view structurally cannot answer.

### Sigma rule support · planned
The current YAML engine is good but bespoke. Supporting Sigma means importing
community rules and exporting detections to any SIEM.

### More bait · planned
Ranked by observed scan volume: Elasticsearch (9200), MongoDB (27017),
PostgreSQL (5432), SMB (445), RDP (3389), VNC (5900).

### Dashboard authentication · planned
The API deliberately ships with none and documents "put it behind a proxy."
OIDC/SSO makes it deployable as-is.

---

## Phase 3 — Reach

- **TAXII server** so other tools can pull indicators; MISP/OpenCTI push
- **Retention and privacy policy** — captured credentials are real people's
  passwords. Automated pruning, optional hashing at rest, a documented handling
  policy. Rare in portfolio projects and the first thing a security team asks.
- **Observability** — Prometheus metrics, Grafana dashboard for sensor health

---

## Running throughout

Not a phase — the habit that makes the rest worth reading.

- **Refresh the evidence.** `docs/live-evidence.md` with real capture counts is
  the most valuable file in this repo.
- **Write up findings.** One short analysis per interesting capture: a Mirai
  loader step by step, a credential-spray campaign, a Docker takeover attempt.
- **Keep the safety properties explicit.** Never executes, never reaches out,
  URLs defanged before they reach a chat channel, synthetic data always labelled.
  Each one is a decision a reviewer can check.
