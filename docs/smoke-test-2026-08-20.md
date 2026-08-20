# Smoke test — 2026-08-20

A quick health check on the live sensor after two days unattended: confirm the
deployed code matches what's pushed, prove the stack still ingests and detects
correctly, and note one documented (not a bug) behaviour that's easy to
mistake for one.

## What was checked

- **Deployed code was stale.** The VM was still on `1fe9486`; two pushes since
  (`4ec250c`, `77f1abc`) had not been pulled. Synced and rebuilt — `git reset
  --hard` to the pushed commit, `docker compose up -d --build`. All four
  containers healthy afterward, zero data loss (Postgres and payload volumes
  persist across rebuilds).
- **Organic growth confirmed.** Event count grew from 5,344 (2026-08-17) to
  **56,014** with no intervention — the sensor kept ingesting unattended for
  three days, which is the property that actually matters for a deployed
  honeypot.
- **New export route verified live.** `GET /api/export/events.jsonl`, added in
  `77f1abc`, returns `200` against the freshly rebuilt image.
- **A small, deliberate probe** — three HTTP requests plus one SSH scenario —
  confirmed the ingest → detect → score pipeline still works end to end after
  the rebuild: 9 new alerts raised, attacker aggregates rebuilt cleanly.

## One thing worth documenting, not fixing

The SSH `credential_stuffing` scenario produced `connect`/`disconnect` events
only — no `auth_attempt`. This is correct, not a regression: the scenario's own
description says *"fingerprinted, not captured"* and its YAML comment explains
why — it exercises the version-exchange + `KEXINIT` HASSH-fingerprinting path
deliberately, without completing a real crypto handshake, so no password ever
reaches the wire for the sensor to record. Credential *capture* over SSH needs
the full `paramiko`-backed mode and a client that actually authenticates;
`iot_botnet_mimic` (telnet) is the scenario built for that. Confirmed correct
in both the scenario comment and `honeypot/services/ssh_service.py`'s
fingerprint/full-mode split — no code change needed.

## Result

Stack healthy, code current, pipeline verified end to end. No adjustments were
required to the platform itself this run.
