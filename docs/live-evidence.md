# Live deployment — working evidence

Proof that the full stack runs end-to-end on a public host and captures,
enriches, detects, scores and visualises real attacker activity.

- **Date:** 2026-08-14
- **Environment:** Azure Ubuntu 22.04 VM (East Asia), Docker Compose
- **Stack:** 4 containers — `sensor`, `api`, `dashboard`, `db` (PostgreSQL) — all healthy
- **Exposure:** bait on public ports 22 (SSH), 23 (Telnet), 80 (HTTP), 21 (FTP);
  admin SSH relocated to a restricted high port; dashboard bound to localhost and
  reached only through an SSH tunnel
- **Automation:** detection + attacker scoring re-run every 5 minutes via cron

## Operational upgrades (live)

Beyond the base sensor, the deployment runs as a full operational system:

- **Six bait services** — SSH, Telnet, FTP, HTTP, **Redis**, **MySQL**. The Redis
  emulator captures the unauthenticated-RCE chain (`CONFIG SET`, `SLAVEOF`,
  `MODULE LOAD`, SSH-key/cron `SET` payloads) and MySQL captures login usernames
  — both executing nothing. New rules `redis_rce_attempt`,
  `redis_dangerous_command`, `mysql_bruteforce` fire on them.
- **Real-time alerting** — newly-raised high/critical alerts push to a
  Slack/Discord/Teams/webhook (idempotent, severity-gated, rate-capped).
- **Threat intelligence** — **159,821 indicators** loaded from blocklist.de,
  ipsum and FireHOL level-1; enrichment now scores known-bad sources (verified:
  a feed IP resolves to score 80 with tags `ti:blocklist-de, ti:ipsum`).
  Refreshed weekly.
- **IOC output** — `/api/export/{blocklist,stix,misp}` serve deployable
  indicators; an hourly cron writes `exports/blocklist.txt` and a STIX bundle.
- **Hardening** — nightly PostgreSQL backups (7-day rotation), 45-day event
  retention pruning, and `fail2ban` guarding the admin SSH port behind the NSG.

## Live metrics (24h window)

| Metric | Value |
| --- | ---: |
| Events captured | **1,172** |
| Sessions | 303 |
| Commands executed in the fake shell | 304 |
| Distinct source IPs | 10 |
| Auth attempts | 52 |
| Distinct credential pairs | 20 |
| Open alerts | **65** (62 high/critical) |

Traffic split: **telnet 511 · http 441 · ssh 220** events.

## Detections that fired (13 rule types)

| Rule | Hits |
| --- | ---: |
| High-volume source | 936 |
| Web path enumeration | 137 |
| Mirai-family command signature | 76 |
| Interactive shell obtained | 48 |
| IoT default credentials used | 42 |
| Second-stage payload fetch | 30 |
| Telnet brute-force | 30 |
| Shellshock exploitation attempt | 15 |
| Exposed secret file probe | 9 |
| Multi-service sweep | 9 |
| Webshell upload attempt | 3 |
| Path traversal attempt | 3 |
| Log4Shell (JNDI) exploitation attempt | 3 |

## Real botnet capture (not simulated)

The passwords panel below shows credentials submitted by sources hitting the
public IP that were **never part of this project's test scenarios** — they came
from live IoT botnets scanning the internet:

`vizxv`, `juantech`, `xmhdipc`, `linuxshell`, `Zte521`, `klv123`, `anko`,
`smcadmin`

These are well-known hardcoded credentials from the Mirai/Gafgyt lineage,
observed in the wild against this sensor. Several sessions reached the emulated
shell and ran the recognisable loader sequence (`/bin/busybox`, `/proc/mounts`,
a `wget` of a second-stage payload), which the sensor recorded without ever
executing or fetching anything.

## Screenshots

### Overview
Headline counters, activity timeline, services targeted, captured
username/password dictionaries, most-probed paths, and the weekday/hour schedule.

![Overview](screenshots/01-overview.png)

### Attackers
Every source scored 0–100 and classified (`botnet-loader`, `recon-scanner`, …),
ranked by threat score.

![Attackers](screenshots/02-attackers.png)

### Alerts
The deduplicated triage queue — one row per condition with a hit counter and
MITRE ATT&CK mapping.

![Alerts](screenshots/03-alerts.png)

### Attacker profile
Per-source dossier with the **transparent score breakdown** (every component and
weight) and the full captured event transcript.

![Attacker profile](screenshots/04-attacker-profile.png)

## How this was verified

1. Deployed the committed `docker-compose.yml` + override on a clean Azure VM;
   all four containers built and reported healthy.
2. Confirmed the bait is reachable from the public internet (fake `Apache/2.4.52`
   HTTP response, Ubuntu telnet banner) and that the dashboard is **not**
   (localhost-bound).
3. Drove the sensor with the in-repo scenario harness *and* observed unsolicited
   real-world scanning; both landed in PostgreSQL through the batched writer.
4. Ran the detection pipeline over 1,162 events → 65 alerts across 13 rules; the
   attacker aggregate scored 10 sources.
5. Rendered every dashboard view against the live API (screenshots above).

## Data-handling note

Source addresses shown are real, mostly-compromised third-party machines, and
the captured credentials are attacker-submitted *guesses* (their dictionary),
not victim secrets. The honeypot's own public IP is intentionally omitted here.
See [FINDINGS.md](../FINDINGS.md) for full handling rules.
