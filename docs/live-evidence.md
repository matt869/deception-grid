# Live deployment — working evidence

Proof that the full stack runs end-to-end on a public host and captures,
enriches, geolocates, detects, scores, alerts on, and exports **real** attacker
activity. Every number below is a live measurement; the raw API snapshot is
committed alongside at [`evidence/metrics-2026-08-14.json`](evidence/metrics-2026-08-14.json).

- **Date:** 2026-08-14
- **Environment:** Azure Ubuntu 22.04 VM (East Asia), Docker Compose
- **Stack:** `sensor`, `api`, `dashboard`, `db` (PostgreSQL) — all healthy
- **Exposure:** six bait services on public ports 22/23/80/21/6379/3306; admin
  SSH relocated + IP-locked; dashboard localhost-only via SSH tunnel
- **Automation:** detection + scoring every 5 min; IOC export hourly; feed +
  backup + retention on cron

## Live metrics (24h window)

| Metric | Value |
| --- | ---: |
| Events captured | **2,871** |
| Distinct source IPs | **37** |
| Countries (geolocated) | **7** |
| Sessions | 609 |
| Commands executed in the fake shell | 1,048 |
| Auth attempts | 202 |
| Distinct credential pairs | 57 |
| Open alerts | **202** (188 critical) |
| Detection rules firing | **17** of 24 |
| `geoip_available` | **true** (DB-IP) |

## Six bait services, all capturing

| Service | Events | Sources |
| --- | ---: | ---: |
| telnet | 1,695 | 18 |
| http | 739 | 9 |
| ssh | 312 | 13 |
| **redis** | 70 | 1 |
| **mysql** | 55 | 3 |

## Detections that fired (17 rule types)

| Rule | Hits | | Rule | Hits |
| --- | ---: | --- | --- | ---: |
| High-volume source | 936 | | Second-stage payload fetch | 50 |
| High enrichment threat score | 214 | | Shellshock attempt | 25 |
| Mirai-family signature | 198 | | **Redis dangerous command** | 24 |
| Interactive shell obtained | 157 | | Exposed secret-file probe | 15 |
| Web path enumeration | 137 | | **MySQL brute-force** | 10 |
| IoT default credentials | 124 | | Multi-service sweep | 9 |
| Telnet brute-force | 70 | | **Redis RCE / persistence** | 6 |
| Log4Shell (JNDI) | 5 | | Path traversal / Webshell upload | 5 / 5 |

## Geolocation working (DB-IP, no license key)

Real sources resolved to country **and** network operator via the free DB-IP
Lite database:

| Country | Events | Top network (ASN) |
| --- | ---: | --- |
| 🇵🇭 Philippines | 496 | ComClark Network & Technology (AS17639) |
| 🇰🇷 South Korea | 50 | LG POWERCOMM (AS17858) |
| 🇭🇰 Hong Kong | 21 | HK Kowloon Telecom (AS135357) |
| 🇨🇳 China | 16 | China Unicom Backbone (AS4837) |
| 🇮🇳 India | 14 | Web Werks India (AS133296) |
| 🇺🇸 United States | 13 | Hurricane Electric (AS6939) |
| 🇳🇱 Netherlands | 9 | UNMANAGED LTD (AS47890) |

## Threat-intel feeds matching real attackers

The 159k-indicator feed set (blocklist.de + ipsum + FireHOL) is not decoration —
it flagged **real** attackers hitting the sensor. These sources carry a live
`ti:` tag from a feed match:

- `103.131.61.163` → `ti:ipsum` (score 99.98, botnet-loader)
- `112.156.166.41` → `ti:ipsum` (🇰🇷 LG POWERCOMM, score 94)
- `206.183.111.36` → `ti:ipsum` (🇮🇳 Web Werks, score 92)

## Real-time Discord alerting (delivered)

New high/critical alerts post to Discord within one detection cycle. Captured
from the channel — the test message plus **real** shell-access alerts whose
source IPs match the attacker table above:

```
🚨 [CRITICAL] Alerting is LIVE — test from honeypot-azure — source 127.0.0.1 · T0000
🚨 [CRITICAL] Interactive shell obtained: 17106059-… — source 103.131.61.163 · T1078
🚨 [CRITICAL] Interactive shell obtained: d4bf5f24-… — source 103.131.61.163 · T1078
🚨 [CRITICAL] Interactive shell obtained: 492f5a2e-… — source 206.183.111.36 · T1078
```

## Top attackers (scored + classified)

| Score | Source | Country | Network | Class | Notable |
| ---: | --- | --- | --- | --- | --- |
| 100 | `136.158.56.92` | 🇵🇭 PH | ComClark | botnet-loader | nuclei scanner; log4shell, shellshock, traversal, webshell |
| 100 | `103.131.61.163` | — | — | botnet-loader | `ti:ipsum`; creds vizxv/linuxshell/smcadmin/juantech |
| 94 | `112.156.166.41` | 🇰🇷 KR | LG POWERCOMM | botnet-loader | `ti:ipsum` |
| 92 | `206.183.111.36` | 🇮🇳 IN | Web Werks | botnet-loader | `ti:ipsum`; posted to Discord |

Research scanners (e.g. **Censys**) are correctly de-ranked to `low-signal`,
showing the scoring separates hostile automation from benign measurement.

## Redis / MySQL bait (new services, working)

The Redis emulator captured the full unauthenticated-RCE chain — `CONFIG SET dir`,
`SLAVEOF`, `MODULE LOAD`, and `SET` of an SSH-key/cron payload — firing
`redis_rce_attempt` (6) and `redis_dangerous_command` (24). MySQL captured login
usernames across sprays, firing `mysql_bruteforce` (10). Both execute nothing.

## Screenshots

### Overview — timeline, origin map, six-service breakdown, credential clouds
![Overview](screenshots/01-overview.png)

### Attackers — 37 sources, geo-flagged, ASN-attributed, scored & classified
![Attackers](screenshots/02-attackers.png)

### Alerts — deduplicated triage queue with MITRE ATT&CK mapping
![Alerts](screenshots/03-alerts.png)

### Attacker profile — transparent score breakdown + full event transcript
![Attacker profile](screenshots/04-attacker-profile.png)

## How this was verified

1. Deployed the committed compose stack on a clean Azure VM; all four containers
   built and reported healthy.
2. Confirmed public reachability of all six bait ports and that the dashboard is
   localhost-bound only.
3. Loaded 159,821 real threat-intel indicators; confirmed feed matches on live
   attackers (`ti:` tags).
4. Installed DB-IP Lite; confirmed geolocation + ASN attribution
   (`geoip_available: true`, 7 countries, real operators).
5. Enabled Discord alerting; confirmed test + real shell-access alerts delivered.
6. Ran detection over 2,871 events → 202 alerts across 17 rules; scored 37 sources.
7. Rendered every dashboard view against the live API (screenshots) and exported
   a deployable blocklist via `/api/export/blocklist`.

## Data-handling note

Source addresses are real, mostly-compromised third-party machines; captured
credentials are attacker-submitted *guesses* (their dictionary), not victim
secrets. The honeypot's own public IP and the Discord webhook are intentionally
omitted. See [FINDINGS.md](../FINDINGS.md).
