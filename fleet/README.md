# fleet/ — multi-sensor coordination

**Status: Phase 1, not yet implemented.** See [../docs/ROADMAP.md](../docs/ROADMAP.md).

Today the sensor writes events straight to the database, which assumes sensor and
database share a host. This package is where that assumption gets removed so many
sensors can report to one backend.

Planned modules:

| Module | Responsibility |
|---|---|
| `ingest.py` | Authenticated event-ingest endpoint; sensors POST batches here |
| `registry.py` | Sensor identity, keys, health, last-seen, version |
| `buffer.py` | Sensor-side local spooling when the collector is unreachable |

**The constraint that shapes this:** a sensor must never drop a capture because
the collector restarted. Local buffering comes before anything else here — the
whole point of the sensor is that it does not miss things.

The existing `honeypot/logger.py` already queues and batches behind a stable
interface, so this arrives as a new sink rather than a rewrite of the hot path.
