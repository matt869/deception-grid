# pipeline/clustering/ — campaign clustering

**Status: Phase 2, not yet implemented.** See [../../docs/ROADMAP.md](../../docs/ROADMAP.md).

Every view in the dashboard is keyed by source IP. That is the right default and
the wrong unit of analysis: one operator rotates through addresses, and a single
address can host unrelated scanners. An IP-keyed view structurally cannot answer
"is this the same operator from a new address?"

Planned modules:

| Module | Responsibility |
|---|---|
| `features.py` | Behavioural feature vector per source — command sequence, credential set, timing, service mix, ASN |
| `campaigns.py` | Cluster sources into campaigns; assign stable campaign IDs |
| `link.py` | Explain *why* two sources were linked, so a merge can be argued with |

**Design note.** Clustering that cannot be interrogated is worse than none: an
analyst who cannot see why two addresses were merged has no way to catch a bad
merge. Follow the scoring model — every verdict shows its components.
