"""Attacker threat scoring and behavioural classification.

The score is a deliberately **transparent additive model**, not a trained
classifier. Each component is bounded, documented and independently inspectable,
so an analyst can always answer "why is this IP 82?" by reading
:func:`score_breakdown`. A black-box model that scores better on average but
cannot justify a single verdict is the wrong trade for triage work, where the
output has to survive being questioned.

Weights are opinionated and meant to be tuned. They encode one judgement:
*what an attacker did* matters more than *how much they did*. A source that
issued one command inside the shell outranks one that sent ten thousand
connection attempts, because volume is cheap and access is not.
"""

from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from typing import Any

from storage.models import Event, EventType, Severity, ensure_utc, utcnow

MAX_SCORE = 100.0

# Component ceilings. These sum to more than MAX_SCORE on purpose — the total is
# clamped, so a source can top out several different ways.
WEIGHTS: dict[str, float] = {
    "volume": 15.0,  # how many events
    "persistence": 12.0,  # how long they stayed / came back
    "credential_breadth": 18.0,  # how many distinct users/passwords tried
    "service_breadth": 8.0,  # how many protocols touched
    "severity": 25.0,  # worst-case severity of what they sent
    "post_exploitation": 30.0,  # shell access, commands, payload fetches
    "threat_intel": 20.0,  # matched a configured indicator
}

# Behavioural classes, checked in order — first match wins, so the most
# specific and most serious patterns come first.
CLASSIFICATIONS = (
    "botnet-loader",
    "targeted-intrusion",
    "exploit-attempt",
    "credential-bruteforce",
    "web-scanner",
    "recon-scanner",
    "opportunistic-probe",
    "low-signal",
)


def _clamp(value: float, ceiling: float) -> float:
    return max(0.0, min(value, ceiling))


def score_breakdown(attacker, events: Sequence[Event]) -> dict[str, float]:
    """Per-component contributions. The audit trail behind the total."""
    if not events:
        return {name: 0.0 for name in WEIGHTS}

    timestamps = [ensure_utc(e.ts) for e in events]
    span_hours = max((max(timestamps) - min(timestamps)).total_seconds() / 3600, 0.0)

    # -- volume: logarithmic. The difference between 10 and 100 events matters;
    #    between 10,000 and 100,000 it does not.
    volume = _clamp(math.log10(len(events) + 1) * 5.0, WEIGHTS["volume"])

    # -- persistence: returning over hours or days is more deliberate than one
    #    burst, regardless of how large the burst was.
    session_ids = {e.session_id for e in events if e.session_id}
    persistence = _clamp(
        math.log1p(span_hours) * 3.0 + math.log1p(len(session_ids)) * 2.0,
        WEIGHTS["persistence"],
    )

    # -- credential breadth
    usernames = {e.username for e in events if e.username}
    passwords = {e.password for e in events if e.password}
    credential_breadth = _clamp(
        math.log1p(len(usernames)) * 4.0 + math.log1p(len(passwords)) * 2.5,
        WEIGHTS["credential_breadth"],
    )

    # -- service breadth
    services = {e.service for e in events if e.service}
    service_breadth = _clamp((len(services) - 1) * 3.0, WEIGHTS["service_breadth"])

    # -- severity: driven by the worst thing seen plus how often high-severity
    #    events recurred, so one critical hit registers immediately.
    ranks = [Severity(e.severity).rank for e in events if e.severity]
    worst = max(ranks, default=0)
    high_count = sum(1 for r in ranks if r >= Severity.HIGH.rank)
    severity = _clamp(worst * 5.0 + math.log1p(high_count) * 3.0, WEIGHTS["severity"])

    # -- post-exploitation: the heaviest component. Reaching the shell at all is
    #    categorically different from knocking on the door.
    auth_success = sum(1 for e in events if e.event_type == EventType.AUTH_SUCCESS.value)
    commands = sum(1 for e in events if e.event_type == EventType.COMMAND.value)
    payload_fetch = sum(
        1
        for e in events
        if "payload-fetch" in (e.tags or []) or "second-stage-url" in (e.tags or [])
    )
    uploads = sum(1 for e in events if e.event_type == EventType.FILE_UPLOAD.value)
    post_exploitation = _clamp(
        auth_success * 8.0 + math.log1p(commands) * 6.0 + payload_fetch * 10.0 + uploads * 6.0,
        WEIGHTS["post_exploitation"],
    )

    # -- threat intel: the max, not the sum. Twenty events from one flagged IP
    #    is one flagged IP, not twenty independent confirmations.
    threat_intel = _clamp(
        max((e.threat_score or 0.0) for e in events) * 0.4, WEIGHTS["threat_intel"]
    )

    return {
        "volume": round(volume, 2),
        "persistence": round(persistence, 2),
        "credential_breadth": round(credential_breadth, 2),
        "service_breadth": round(service_breadth, 2),
        "severity": round(severity, 2),
        "post_exploitation": round(post_exploitation, 2),
        "threat_intel": round(threat_intel, 2),
    }


def classify(attacker, events: Sequence[Event]) -> tuple[str, list[str]]:
    """Assign a behavioural class and descriptive tags."""
    if not events:
        return "low-signal", []

    tags: list[str] = []
    all_tags = {tag for e in events for tag in (e.tags or [])}
    all_threat_tags = {tag for e in events for tag in (e.threat_tags or [])}
    services = {e.service for e in events if e.service}
    event_types = {e.event_type for e in events}

    usernames = {e.username for e in events if e.username}
    passwords = {e.password for e in events if e.password}
    paths = {e.path for e in events if e.path}
    auth_attempts = sum(1 for e in events if e.event_type == EventType.AUTH_ATTEMPT.value)
    commands = sum(1 for e in events if e.event_type == EventType.COMMAND.value)

    # Carry through the descriptive tags enrichment already established.
    for tag in sorted(all_threat_tags):
        if tag.startswith(("scanner:", "research:", "malware:", "tool:", "ti:")):
            tags.append(tag)
    if "hosting-provider" in all_threat_tags:
        tags.append("from-hosting-provider")
    if "vpn-or-tor" in all_threat_tags:
        tags.append("from-vpn-or-tor")

    exploit_tags = {
        "log4shell",
        "shellshock",
        "sql-injection",
        "path-traversal",
        "command-injection",
        "webshell-upload",
        "env-file-probe",
    }
    matched_exploits = sorted(all_tags & exploit_tags)
    tags.extend(matched_exploits)

    # -- ordered classification -----------------------------------------
    if "mirai-signature" in all_tags or "iot-default-credential" in all_tags:
        tags.append("iot-botnet")
        return "botnet-loader", _dedupe(tags)

    if commands >= 3 and EventType.AUTH_SUCCESS.value in event_types:
        tags.append("hands-on-keyboard")
        return "targeted-intrusion", _dedupe(tags)

    if matched_exploits:
        return "exploit-attempt", _dedupe(tags)

    if auth_attempts >= 10 or len(passwords) >= 8:
        if len(usernames) >= 8:
            tags.append("username-list-driven")
        else:
            tags.append("single-account-focus")
        return "credential-bruteforce", _dedupe(tags)

    if "http" in services and len(paths) >= 15:
        tags.append("path-enumeration")
        return "web-scanner", _dedupe(tags)

    if len(services) >= 3:
        tags.append("multi-protocol")
        return "recon-scanner", _dedupe(tags)

    if len(events) >= 5 or auth_attempts >= 1:
        return "opportunistic-probe", _dedupe(tags)

    return "low-signal", _dedupe(tags)


def score_attacker(attacker, events: Sequence[Event]) -> tuple[float, str, list[str]]:
    """Return ``(score, classification, tags)`` for one attacker.

    This is the function ``storage.queries.rebuild_attackers`` calls.
    """
    if not events:
        return 0.0, "low-signal", []

    breakdown = score_breakdown(attacker, events)
    total = _clamp(sum(breakdown.values()), MAX_SCORE)
    classification, tags = classify(attacker, events)

    # Recency decay: an IP that was noisy last month should not sit at the top
    # of today's queue forever. Nothing decays below 40% of its earned score,
    # because history still matters for attribution.
    last_seen = max(ensure_utc(e.ts) for e in events)
    age_days = max((utcnow() - last_seen).total_seconds() / 86400, 0.0)
    decay = max(0.4, math.exp(-age_days / 30.0))

    return round(total * decay, 2), classification, tags


def explain(attacker, events: Sequence[Event]) -> dict[str, Any]:
    """Full, human-readable justification for an attacker's score."""
    breakdown = score_breakdown(attacker, events)
    score, classification, tags = score_attacker(attacker, events)
    last_seen = max((ensure_utc(e.ts) for e in events), default=None)
    age_days = (utcnow() - last_seen).total_seconds() / 86400 if last_seen else 0.0

    return {
        "score": score,
        "raw_score": round(sum(breakdown.values()), 2),
        "classification": classification,
        "tags": tags,
        "components": breakdown,
        "weights": WEIGHTS,
        "recency_decay": round(max(0.4, math.exp(-age_days / 30.0)), 3),
        "age_days": round(age_days, 2),
        "events_considered": len(events),
    }


def severity_for_score(score: float) -> str:
    """Map a numeric score onto a severity band for display."""
    if score >= 80:
        return Severity.CRITICAL.value
    if score >= 60:
        return Severity.HIGH.value
    if score >= 35:
        return Severity.MEDIUM.value
    if score >= 15:
        return Severity.LOW.value
    return Severity.INFO.value


def _dedupe(items: Iterable[str]) -> list[str]:
    """Order-preserving deduplication."""
    return list(dict.fromkeys(items))


__all__ = [
    "score_attacker",
    "score_breakdown",
    "classify",
    "explain",
    "severity_for_score",
    "WEIGHTS",
    "CLASSIFICATIONS",
    "MAX_SCORE",
]
