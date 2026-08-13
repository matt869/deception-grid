# Event schema

Every observation the sensor makes is one `Event` row. This is the contract the
whole system is built on — the honeypot writes it, the pipeline enriches and
scores it, the API serves it, the dashboard renders it. The authoritative
definition is [`storage/models.py`](../storage/models.py); this document
explains the fields and their intended use.

## Design choices

- **Enrichment is flattened onto the event** (country, ASN, score), not kept in
  a side table. Events are write-once, read-constantly; denormalising avoids a
  three-way join on every dashboard query.
- **Enums are stored as strings**, not native DB enums, so adding a service or
  event type never needs a migration.
- **`geo_source` is always present** and is the field that tells you whether to
  trust the geo columns (see below). This is deliberate: missing or synthetic
  data must be distinguishable from a measurement.

## Core fields

| Field | Type | Notes |
|-------|------|-------|
| `event_id` | str (uuid) | Stable unique id; the cursor for incremental polling. |
| `ts` | datetime (UTC) | When it happened. Always tz-aware on read (`ensure_utc`). |
| `session_id` | str | FK to the `sessions` row — ties one TCP conversation together. |
| `sensor` | str | Which sensor recorded it. Imported data carries the source name. |
| `service` | str | `ssh` \| `telnet` \| `ftp` \| `http`. |
| `event_type` | str | See event types below. |
| `severity` | str | `info` \| `low` \| `medium` \| `high` \| `critical`. |

## Network

| Field | Type | Notes |
|-------|------|-------|
| `src_ip` | str | Source address (IPv4/IPv6). |
| `src_port` | int | Source port. |
| `dst_port` | int | The honeypot port that was hit. |
| `transport` | str | `tcp`. |

## Activity (populated per event type)

| Field | Type | Present on |
|-------|------|-----------|
| `username`, `password` | str | `auth_attempt`, `auth_success` |
| `command` | str | `command` (the fake-shell input) |
| `http_method`, `path`, `user_agent`, `status_code`, `headers` | | `http_request` |
| `payload_sha256`, `payload_size` | | any event carrying a body; payload stored by hash in `data/payloads/` |

## Enrichment (added by the pipeline, not the sensor)

| Field | Type | Notes |
|-------|------|-------|
| `country`, `country_name`, `city`, `latitude`, `longitude` | | Geolocation, or all null. |
| `asn`, `as_org` | | Network ownership, or null. |
| `geo_source` | str | **Read this before trusting geo.** See values below. |
| `threat_score` | float | Per-event enrichment score (indicator + UA + username signals). |
| `threat_tags` | list | e.g. `scanner:zgrab`, `malware:mozi`, `hosting-provider`, `ti:<source>`. |

### `geo_source` values

| Value | Meaning |
|-------|---------|
| `geolite2` | Real MaxMind lookup. Trust the coordinates. |
| `synthetic` | **Generated demo data.** Never a real measurement. |
| `unavailable` | No database present; no lookup was possible. Country is null. |
| `not-found` | Address not in the database (unallocated space). |
| `private` / `loopback` / `link-local` / `reserved` | Non-routable source; not geolocated on purpose. |
| `invalid-address` | `src_ip` did not parse. |

The rule: **only `geolite2` is a measurement.** Everything else means "not
looked up" or "made up for a demo," and the dashboard treats them accordingly —
synthetic/absent points are never plotted as if real.

## Classification

| Field | Type | Notes |
|-------|------|-------|
| `severity` | str | Worst-case interpretation of this single event. |
| `tags` | list | Detection-relevant markers set by the service, e.g. `iot-default-credential`, `mirai-signature`, `payload-fetch`, `log4shell`, `path-traversal`. Rules match on these. |
| `extra` | dict | Anything service-specific: SSH `hassh`, client version, refusal reasons, etc. |

## Event types

| `event_type` | Emitted when |
|--------------|-------------|
| `connect` | A connection opens (also SSH version exchange / HASSH). |
| `auth_attempt` | Any login attempt. |
| `auth_success` | A service "accepts" a login (see `ACCEPT_LOGIN_RATE`). |
| `command` | A command is run in the fake shell. |
| `http_request` | An HTTP request is parsed. |
| `file_upload` | An upload is attempted (FTP STOR, HTTP body). |
| `disconnect` | The connection closes (carries the reason). |
| `error` | Malformed input or a handler error — the sensor stays up. |

## JSONL export

The same schema is written to `data/events.jsonl` (if enabled) and by
`pipeline.reporting.export --format jsonl`, one JSON object per line, with `ts`
as ISO-8601. That file re-imports cleanly via
`tools/import_public_logs.py --format jsonl`, so a sensor's output is portable.

## The GeoLite2 database

Real geolocation needs a MaxMind GeoLite2 `.mmdb` in `data/geolite2/`
(`GeoLite2-City.mmdb`, and `GeoLite2-ASN.mmdb` for ASN). It is **free but
licensed, and not redistributed with this project** — create a free MaxMind
account, download it, and drop it in. Without it the sensor runs fine;
geolocation is simply `unavailable`. As an offline alternative for ASN, drop a
`data/asn_prefixes.tsv` (`prefix<TAB>asn<TAB>org` per line) and the enrichment
uses a longest-prefix match against it.
