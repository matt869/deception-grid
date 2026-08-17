# pipeline/analysis/ — captured payload analysis

**Status: Phase 2, not yet implemented.** See [../../docs/ROADMAP.md](../../docs/ROADMAP.md).

The sensor already captures droppers and stores them by SHA256 under the payload
directory, deduplicated by content hash. Nothing reads them back yet. This is
where that happens.

Planned modules:

| Module | Responsibility |
|---|---|
| `static.py` | File type, ELF/PE structure, entropy, embedded strings and URLs |
| `yara_scan.py` | Match captured payloads against a local rule set |
| `report.py` | Attach findings to the attacker profile that fetched the payload |

**Constraints that do not move:**

- **Nothing is ever executed.** Static analysis only — no sandbox, no emulation.
- **Nothing is ever fetched.** URLs found inside a payload are recorded as
  intelligence, exactly as the fake shell already treats them.
- Extracted URLs are defanged before they appear in any report or notification.
