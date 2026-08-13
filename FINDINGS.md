# Findings & handling notes

This file is two things: a place to record what a deployment of this sensor
actually observed, and — more importantly for a shared repo — the rules for
handling what a honeypot collects. Read the handling section before you run this
against real traffic.

---

## Data handling rules

A honeypot collects things that are sensitive in ways that are easy to
underestimate. These are not optional niceties.

### Captured credentials are often real, and belong to real people

Attackers reuse credential dumps. The username/password pairs this sensor
records are frequently **real credentials for real accounts** — sometimes the
attacker's own reused password, sometimes a victim's harvested from a breach.
Treat the credential store as sensitive personal data:

- Set `API_REDACT_PASSWORDS=1` on any dashboard reachable beyond the security
  team.
- Consider `HASH_PASSWORDS=true` where policy requires it (you lose cleartext
  credential analysis, which is a real trade-off — decide deliberately).
- Do not paste captured credentials into tickets, chat, or screenshots that
  outlive the investigation.

### Captured payloads are live malware

`data/payloads/` contains attacker-uploaded bytes, stored by content hash. Some
of it is functioning malware. It is inert on disk, but:

- Never execute a captured payload outside an isolated analysis environment.
- The payload directory is git-ignored for a reason — do not commit it.
- Second-stage URLs recorded from the fake shell point at live malware
  distribution hosts. **The sensor never fetches them and neither should you**,
  except from an environment built for it.

### Source addresses belong to third parties

The attacking IPs are usually compromised third-party machines — someone else's
hacked router, a bulletproof-host VM, a residential box in a botnet. Before you
publish or act on them:

- Validate before blocklisting. Shared NAT, CGNAT and cloud egress addresses
  show up here too; a naive blocklist blocks bystanders and researchers.
- Indicator exports (`pipeline.reporting.export`) apply a score floor and MISP
  distribution defaults to organisation-only for this reason. Widen scope
  deliberately.

### Imported public datasets carry all of the above

Importing a public Cowrie dataset (`tools/import_public_logs.py`) brings in other
people's captured credentials and real source addresses. Imported rows are
stamped with their source sensor and `extra.imported_from`, so you can always
tell imported history from your own capture — but the handling rules are the
same.

---

## Notable observations

_Record noteworthy campaigns, novel payloads, and interesting sources here as a
deployment runs. The daily digest (`python -m pipeline.reporting.daily_summary`)
is a good source of raw material._

### Template

```
### YYYY-MM-DD — <short title>

- **Source(s):** <ip / ASN / country>
- **Classification:** <botnet-loader | targeted-intrusion | …>  Score: <n>
- **Services:** <ssh/telnet/http/…>
- **What happened:** <the sequence, in plain language>
- **Payload URLs / hashes:** <if any — do not fetch>
- **MITRE:** <technique IDs from the alerts>
- **Action taken:** <blocked / reported / watched / exported to TIP>
```

### Example (from the seeded demo dataset)

> Illustrative only — this is generated synthetic data (reserved IP ranges,
> `synthetic` enrichment), included so the format is concrete.

```
### 2026-08-13 — IoT botnet loader, full Mirai sequence

- Source(s): 198.51.100.79 (TEST-NET-2, synthetic)
- Classification: botnet-loader   Score: 71
- Services: telnet
- What happened: default-credential login (root/xc3511 and others from the
  Mirai list), shell granted, then the recognisable loader sequence —
  `/bin/busybox ECCHI`, `cat /proc/mounts`, `wget …/mirai.arm7`, `chmod +x`,
  execute, `rm`. Post-exploitation and severity score components both maxed.
- Payload URLs: hxxp://198.51.100.77/bins/mirai.arm7  (recorded, never fetched)
- MITRE: T1078.001, T1059.004, T1105
- Action taken: n/a (synthetic demo data)
```
