"""MITRE ATT&CK coverage.

Answers two questions a detection engineer is always asked, and which a list of
rules cannot answer on its own:

1. **What do we detect?** Which ATT&CK techniques the rule set claims to cover.
2. **What has ever actually fired?** Which of those claims are backed by a real
   alert, and which have never triggered once.

The second question is the honest one. A rule that exists but has never fired is
not coverage — it is an untested assertion. It might be perfectly written and
simply describing behaviour nobody has aimed at this sensor yet, or it might be
silently broken. This module refuses to collapse those two states into a green
tick: a technique is ``covered`` only if a rule claims it *and* an alert exists.

Technique → tactic mapping is a local table rather than a download. It covers
exactly the techniques this rule set references, and stays offline-first like
the rest of the pipeline. Adding a rule with a new technique adds a row here;
:func:`unmapped_techniques` reports any that were missed rather than hiding them.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from pipeline.detection.rules import load_rules
from storage.models import Alert, ensure_utc, utcnow

# ATT&CK Enterprise. Where a technique spans several tactics, the one listed is
# the tactic it serves *in this sensor's context* — a honeypot observes Valid
# Accounts as an initial-access attempt, not as persistence.
TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.001": ("Default Accounts", "Initial Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1003.008": ("OS Credential Dumping: /etc/passwd and /etc/shadow", "Credential Access"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1610": ("Deploy Container", "Execution"),
    "T1611": ("Escape to Host", "Privilege Escalation"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1505.003": ("Server Software Component: Web Shell", "Persistence"),
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1496": ("Resource Hijacking", "Impact"),
}

# Kill-chain order, so the report reads left-to-right like the ATT&CK matrix
# rather than alphabetically.
TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

UNKNOWN_TACTIC = "Unmapped"


def _technique_meta(technique: str) -> tuple[str, str]:
    return TECHNIQUES.get(technique, (technique, UNKNOWN_TACTIC))


def rule_techniques() -> dict[str, list[dict[str, str]]]:
    """Technique ID → the enabled rules claiming it."""
    claims: dict[str, list[dict[str, str]]] = {}
    for rule in load_rules():
        if not rule.enabled:
            continue
        for technique in rule.mitre or []:
            claims.setdefault(technique, []).append(
                {"rule_id": rule.id, "rule_name": rule.name, "severity": rule.severity}
            )
    return claims


def unmapped_techniques() -> list[str]:
    """Techniques referenced by rules but missing from :data:`TECHNIQUES`.

    Surfaced rather than swallowed: a technique with no tactic silently lands in
    an "Unmapped" bucket, and a report nobody can explain is worse than a gap
    somebody can fix.
    """
    return sorted(t for t in rule_techniques() if t not in TECHNIQUES)


def _alert_hits(db: OrmSession, since_hours: float | None) -> dict[str, dict[str, Any]]:
    """Per-technique alert totals over the window.

    ``mitre`` is a JSON list column, so this counts in Python rather than with a
    dialect-specific JSON query — the same choice the rest of the query layer
    makes, and at alert volumes (thousands, not millions) it costs nothing.
    """
    stmt = select(Alert.mitre, Alert.hit_count, Alert.last_seen, Alert.severity)
    if since_hours is not None:
        stmt = stmt.where(Alert.last_seen >= utcnow() - dt.timedelta(hours=since_hours))

    hits: dict[str, dict[str, Any]] = {}
    for mitre, hit_count, last_seen, severity in db.execute(stmt):
        for technique in mitre or []:
            row = hits.setdefault(
                technique,
                {"alerts": 0, "hits": 0, "last_seen": None, "worst_severity": None},
            )
            row["alerts"] += 1
            row["hits"] += int(hit_count or 0)
            seen = ensure_utc(last_seen)
            if seen and (row["last_seen"] is None or seen > row["last_seen"]):
                row["last_seen"] = seen
            if _worse(severity, row["worst_severity"]):
                row["worst_severity"] = severity
    return hits


def _worse(candidate: str | None, current: str | None) -> bool:
    from storage.models import Severity

    if candidate is None:
        return False
    if current is None:
        return True
    try:
        return Severity(candidate).rank > Severity(current).rank
    except ValueError:
        return False


def coverage_report(db: OrmSession, since_hours: float | None = None) -> dict[str, Any]:
    """Rule coverage cross-referenced with what has actually fired.

    ``since_hours=None`` reports over all history, which is the right default
    for a coverage question — "has this ever fired" is more useful than "did it
    fire today". Pass a window to ask the narrower question.
    """
    claims = rule_techniques()
    hits = _alert_hits(db, since_hours)

    techniques: list[dict[str, Any]] = []
    for technique, rules in claims.items():
        name, tactic = _technique_meta(technique)
        hit = hits.get(technique)
        techniques.append(
            {
                "technique": technique,
                "name": name,
                "tactic": tactic,
                "rules": rules,
                "rule_count": len(rules),
                "alerts": hit["alerts"] if hit else 0,
                "hits": hit["hits"] if hit else 0,
                "worst_severity": hit["worst_severity"] if hit else None,
                "last_seen": hit["last_seen"].isoformat() if hit and hit["last_seen"] else None,
                # The distinction this module exists to preserve.
                "status": "observed" if hit else "rule-only",
            }
        )

    # Alerts can carry a technique no current rule claims — a rule was renamed or
    # disabled after firing. Worth showing: it is real observed activity.
    for technique, hit in hits.items():
        if technique in claims:
            continue
        name, tactic = _technique_meta(technique)
        techniques.append(
            {
                "technique": technique,
                "name": name,
                "tactic": tactic,
                "rules": [],
                "rule_count": 0,
                "alerts": hit["alerts"],
                "hits": hit["hits"],
                "worst_severity": hit["worst_severity"],
                "last_seen": hit["last_seen"].isoformat() if hit["last_seen"] else None,
                "status": "orphaned",
            }
        )

    techniques.sort(key=_sort_key)

    by_tactic: dict[str, list[dict[str, Any]]] = {}
    for row in techniques:
        by_tactic.setdefault(row["tactic"], []).append(row)

    observed = sum(1 for t in techniques if t["status"] == "observed")
    rule_only = sum(1 for t in techniques if t["status"] == "rule-only")

    return {
        "generated_at": utcnow().isoformat(),
        "window_hours": since_hours,
        "tactics": [t for t in TACTIC_ORDER if t in by_tactic]
        + ([UNKNOWN_TACTIC] if UNKNOWN_TACTIC in by_tactic else []),
        "by_tactic": by_tactic,
        "techniques": techniques,
        "totals": {
            "techniques_claimed": len(claims),
            "techniques_observed": observed,
            "techniques_rule_only": rule_only,
            "techniques_orphaned": sum(1 for t in techniques if t["status"] == "orphaned"),
            "rules_enabled": sum(1 for r in load_rules() if r.enabled),
            # Deliberately *not* called "coverage %": it is the share of claimed
            # techniques with evidence behind them, which is a different claim.
            "observed_share": round(observed / len(claims), 3) if claims else 0.0,
        },
        "unmapped": unmapped_techniques(),
    }


def _sort_key(row: dict[str, Any]) -> tuple[int, str]:
    tactic = row["tactic"]
    index = TACTIC_ORDER.index(tactic) if tactic in TACTIC_ORDER else len(TACTIC_ORDER)
    return (index, row["technique"])


__all__ = [
    "coverage_report",
    "rule_techniques",
    "unmapped_techniques",
    "TECHNIQUES",
    "TACTIC_ORDER",
]
