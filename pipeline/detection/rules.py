"""Rule engine.

Loads ``rules.yaml``, evaluates each rule against a window of events, and
upserts :class:`~storage.models.Alert` rows.

Two things shape the design:

**Deduplication.** A brute-force rule that fires per matching event produces
hundreds of identical alerts and buries everything else. Each rule instead emits
one alert per ``(rule_id, group_by value)``; re-firing bumps ``hit_count`` and
``last_seen``. The analyst sees one row that grows, which is what they actually
want to triage.

**Evaluation is a pure function of the window.** :func:`evaluate_rules` reads
events and returns alert dicts; persistence is separate. That makes rules
testable without a database and means a rule change can be replayed over
historical events to see what it *would* have caught.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from storage.models import Alert, Event, Severity, ensure_utc, utcnow

log = logging.getLogger("pipeline.detection")

RULES_PATH = Path(__file__).resolve().parent / "rules.yaml"

VALID_TYPES = {"threshold", "distinct", "match", "ratio"}


class RuleError(ValueError):
    """Raised when a rule definition is malformed."""


@dataclass(slots=True)
class Rule:
    id: str
    name: str
    severity: str
    type: str
    description: str = ""
    enabled: bool = True
    window_minutes: int = 60
    group_by: str = "src_ip"
    threshold: float = 1
    distinct_field: str | None = None
    where: dict[str, Any] = field(default_factory=dict)
    numerator_where: dict[str, Any] = field(default_factory=dict)
    mitre: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if self.type not in VALID_TYPES:
            raise RuleError(f"rule {self.id}: unknown type {self.type!r}")
        try:
            Severity(self.severity)
        except ValueError as exc:
            raise RuleError(f"rule {self.id}: bad severity {self.severity!r}") from exc
        if self.type == "distinct" and not self.distinct_field:
            raise RuleError(f"rule {self.id}: type 'distinct' requires distinct_field")
        if self.type == "ratio" and not self.numerator_where:
            raise RuleError(f"rule {self.id}: type 'ratio' requires numerator_where")
        if self.window_minutes <= 0:
            raise RuleError(f"rule {self.id}: window_minutes must be positive")


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #


def load_rules(path: Path | str | None = None) -> list[Rule]:
    """Parse and validate the rule file.

    Raises on the first malformed rule rather than skipping it: a detection that
    silently does not load is worse than one that loudly refuses to start.
    """
    rules_path = Path(path) if path else RULES_PATH
    if not rules_path.exists():
        log.warning("no rule file at %s; detection disabled", rules_path)
        return []

    raw = yaml.safe_load(rules_path.read_text(encoding="utf-8")) or {}
    entries = raw.get("rules", [])
    if not isinstance(entries, list):
        raise RuleError(f"{rules_path}: 'rules' must be a list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or "id" not in entry:
            raise RuleError(f"{rules_path}: every rule needs an 'id'")
        if entry["id"] in seen:
            raise RuleError(f"{rules_path}: duplicate rule id {entry['id']!r}")
        seen.add(entry["id"])

        known = {f for f in Rule.__slots__}
        unknown = set(entry) - known
        if unknown:
            raise RuleError(f"rule {entry['id']}: unknown key(s) {sorted(unknown)}")

        rule = Rule(**{k: v for k, v in entry.items() if k in known})
        rule.description = (rule.description or "").strip()
        rule.validate()
        rules.append(rule)

    log.info(
        "loaded %d detection rules (%d enabled)", len(rules), sum(1 for r in rules if r.enabled)
    )
    return rules


# --------------------------------------------------------------------------- #
# Condition matching
# --------------------------------------------------------------------------- #


def _event_value(event: Event, name: str) -> Any:
    return getattr(event, name, None)


def matches(event: Event, conditions: dict[str, Any]) -> bool:
    """Evaluate a rule's ``where`` block against one event. All must hold."""
    for key, expected in conditions.items():
        if "__" in key:
            field_name, _, operator = key.partition("__")
        else:
            field_name, operator = key, "eq"

        actual = _event_value(event, field_name)

        if operator == "eq":
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False

        elif operator == "contains":
            if actual is None or str(expected).lower() not in str(actual).lower():
                return False

        elif operator == "in_tags":
            tags = actual or []
            if not isinstance(tags, (list, tuple)) or expected not in tags:
                return False

        elif operator == "gte":
            if actual is None or float(actual) < float(expected):
                return False

        elif operator == "lte":
            if actual is None or float(actual) > float(expected):
                return False

        elif operator == "isnull":
            if (actual is None) != bool(expected):
                return False

        else:
            raise RuleError(f"unknown operator {operator!r} in condition {key!r}")

    return True


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #


def evaluate_rule(
    rule: Rule, events: Sequence[Event], now: dt.datetime | None = None
) -> list[dict[str, Any]]:
    """Evaluate one rule against a sequence of events.

    ``window_minutes`` is applied as a **sliding window over the events
    themselves**, not as "the last N minutes before now". The rule fires if
    *any* N-minute span in the data satisfies it.

    This is the only semantics that is correct in both directions. Anchoring the
    window to wall-clock now means a rule can only ever fire on events from the
    last few minutes, so replaying yesterday's traffic — or a seeded dataset, or
    an imported log — detects nothing, and a scheduled run that lands a minute
    late silently misses the burst it was written to catch. Sliding the window
    makes detection a property of the data, which also makes it reproducible:
    the same events always produce the same alerts.

    Pure — no database access, no mutation of ``events``.
    """
    if not rule.enabled:
        return []

    candidates = [e for e in events if matches(e, rule.where)] if rule.where else list(events)
    if not candidates:
        return []

    grouped: dict[Any, list[Event]] = defaultdict(list)
    for event in candidates:
        key = _event_value(event, rule.group_by)
        if key is None:
            continue
        grouped[key].append(event)

    window = dt.timedelta(minutes=rule.window_minutes)

    alerts: list[dict[str, Any]] = []
    for key, group in grouped.items():
        observed, triggered, evidence_events = _test_group(rule, group, window)
        if triggered:
            alerts.append(_build_alert(rule, key, evidence_events or group, observed))

    return alerts


def _sliding_peak(
    events: list[Event],
    window: dt.timedelta,
    distinct_field: str | None = None,
) -> tuple[int, list[Event]]:
    """Peak count within any ``window``-length span, and the events achieving it.

    Two-pointer scan over time-ordered events: O(n log n) for the sort, O(n)
    for the scan. Counts raw events, or distinct values of ``distinct_field``
    when given.
    """
    ordered = sorted(events, key=lambda e: ensure_utc(e.ts))
    if not ordered:
        return 0, []

    best = 0
    best_span: list[Event] = []
    counter: Counter = Counter()
    left = 0

    for right, event in enumerate(ordered):
        if distinct_field is not None:
            value = _event_value(event, distinct_field)
            if value is not None:
                counter[value] += 1

        # Shrink from the left until the span fits inside the window.
        while ensure_utc(ordered[right].ts) - ensure_utc(ordered[left].ts) > window:
            if distinct_field is not None:
                stale = _event_value(ordered[left], distinct_field)
                if stale is not None:
                    counter[stale] -= 1
                    if counter[stale] == 0:
                        del counter[stale]
            left += 1

        current = len(counter) if distinct_field is not None else (right - left + 1)
        if current > best:
            best = current
            best_span = ordered[left : right + 1]

    return best, best_span


def _test_group(
    rule: Rule, group: list[Event], window: dt.timedelta
) -> tuple[float, bool, list[Event]]:
    """Return ``(observed_value, did_it_trigger, evidence_events)``."""
    if rule.type == "match":
        # Presence rules have no threshold: one matching event is the finding.
        return float(len(group)), True, group

    if rule.type == "threshold":
        peak, span = _sliding_peak(group, window)
        return float(peak), peak >= rule.threshold, span

    if rule.type == "distinct":
        peak, span = _sliding_peak(group, window, distinct_field=rule.distinct_field)
        return float(peak), peak >= rule.threshold, span

    if rule.type == "ratio":
        if not group:
            return 0.0, False, []
        numerator = sum(1 for e in group if matches(e, rule.numerator_where))
        ratio = numerator / len(group)
        return round(ratio, 4), ratio >= rule.threshold, group

    raise RuleError(f"rule {rule.id}: unhandled type {rule.type!r}")  # pragma: no cover


def _build_alert(rule: Rule, key: Any, group: list[Event], observed: float) -> dict[str, Any]:
    timestamps = [ensure_utc(e.ts) for e in group]
    sample = group[0]

    # The grouping key is not always src_ip (password spray groups by password),
    # so resolve the attribution fields from the events themselves.
    src_ips = {e.src_ip for e in group if e.src_ip}
    services = sorted({e.service for e in group if e.service})

    evidence: dict[str, Any] = {
        "observed": observed,
        "threshold": rule.threshold,
        "matching_events": len(group),
        "window_minutes": rule.window_minutes,
        "group_by": rule.group_by,
        "group_value": str(key),
        "services": services,
        "source_ips": sorted(src_ips)[:20],
        "first_event": min(timestamps).isoformat(),
        "last_event": max(timestamps).isoformat(),
        "sample_event_ids": [e.event_id for e in group[:5]],
    }

    if rule.type == "distinct" and rule.distinct_field:
        values = sorted(
            {
                str(_event_value(e, rule.distinct_field))
                for e in group
                if _event_value(e, rule.distinct_field) is not None
            }
        )
        evidence["distinct_field"] = rule.distinct_field
        evidence["distinct_values_sample"] = values[:25]

    commands = [e.command for e in group if e.command]
    if commands:
        evidence["commands"] = commands[:10]
    paths = sorted({e.path for e in group if e.path})
    if paths:
        evidence["paths_sample"] = paths[:25]

    title = _format_title(rule, key, observed)

    return {
        "alert_id": str(uuid.uuid4()),
        "rule_id": rule.id,
        "rule_name": rule.name,
        "severity": rule.severity,
        "src_ip": sample.src_ip if rule.group_by != "src_ip" else str(key),
        "session_id": sample.session_id if rule.group_by == "session_id" else None,
        "service": services[0] if len(services) == 1 else None,
        "title": title,
        "description": rule.description,
        "evidence": evidence,
        "mitre": rule.mitre,
        "first_seen": min(timestamps),
        "last_seen": max(timestamps),
        "hit_count": len(group),
        "dedupe_key": f"{rule.id}|{key}",
    }


def _format_title(rule: Rule, key: Any, observed: float) -> str:
    if rule.type == "threshold":
        return f"{rule.name}: {int(observed)} events from {key}"
    if rule.type == "distinct":
        return f"{rule.name}: {int(observed)} distinct {rule.distinct_field} from {key}"
    if rule.type == "ratio":
        return f"{rule.name}: ratio {observed:.0%} for {key}"
    return f"{rule.name}: {key}"


def evaluate_rules(
    events: Sequence[Event],
    rules: Sequence[Rule] | None = None,
    now: dt.datetime | None = None,
) -> list[dict[str, Any]]:
    """Evaluate every enabled rule and return all alert dicts."""
    active = rules if rules is not None else load_rules()
    alerts: list[dict[str, Any]] = []
    for rule in active:
        try:
            alerts.extend(evaluate_rule(rule, events, now=now))
        except Exception as exc:  # noqa: BLE001
            # One broken rule must not stop the other twenty from running.
            log.error("rule %s failed to evaluate: %s", rule.id, exc, exc_info=True)
    return alerts


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


def persist_alerts(
    db, alert_dicts: Iterable[dict[str, Any]]
) -> tuple[int, int, list[dict[str, Any]]]:
    """Upsert alerts by ``dedupe_key``.

    Returns ``(created, updated, created_payloads)``. The third element is the
    list of alerts that were *newly* created this run — the pipeline notifies on
    exactly those, so repeated idempotent runs don't re-page.
    """
    from sqlalchemy import select

    created = updated = 0
    created_payloads: list[dict[str, Any]] = []
    for payload in alert_dicts:
        existing = db.execute(
            select(Alert).where(Alert.dedupe_key == payload["dedupe_key"])
        ).scalar_one_or_none()

        if existing is None:
            db.add(Alert(**payload))
            created += 1
            created_payloads.append(payload)
            continue

        # hit_count takes the max, not a sum. With sliding-window evaluation the
        # incoming value is the peak intensity recomputed from the events, so
        # adding it would double-count every time detection re-runs over the
        # same data — which the scheduler does by design. max() keeps the run
        # idempotent while still ratcheting up when a campaign intensifies.
        existing.hit_count = max(existing.hit_count, payload["hit_count"])
        existing.last_seen = max(ensure_utc(existing.last_seen), ensure_utc(payload["last_seen"]))
        existing.first_seen = min(
            ensure_utc(existing.first_seen), ensure_utc(payload["first_seen"])
        )
        existing.evidence = payload["evidence"]
        existing.severity = payload["severity"]
        existing.title = payload["title"]
        db.add(existing)
        updated += 1

    db.flush()
    return created, updated, created_payloads


def run_detection(
    db,
    since_hours: float = 24,
    rules: Sequence[Rule] | None = None,
) -> dict[str, Any]:
    """Load recent events, evaluate every rule, persist the results."""
    from sqlalchemy import select

    window_start = utcnow() - dt.timedelta(hours=since_hours)
    events = list(
        db.execute(select(Event).where(Event.ts >= window_start).order_by(Event.ts)).scalars()
    )

    active = list(rules) if rules is not None else load_rules()
    alert_dicts = evaluate_rules(events, active)
    created, updated, created_payloads = persist_alerts(db, alert_dicts)

    # Push notifications for newly-raised alerts only (best-effort, never fatal).
    notify_stats = {"enabled": 0, "sent": 0, "failed": 0}
    if created_payloads:
        try:
            from pipeline.alerting import notify_new_alerts

            notify_stats = notify_new_alerts(created_payloads)
        except Exception as exc:  # noqa: BLE001 - notifications must never break detection
            log.warning("alert notification dispatch failed: %s", exc)

    log.info(
        "detection over %d events: %d alerts (%d new, %d updated); notified=%d",
        len(events),
        len(alert_dicts),
        created,
        updated,
        notify_stats.get("sent", 0),
    )
    return {
        "events_evaluated": len(events),
        "rules_evaluated": sum(1 for r in active if r.enabled),
        "alerts_generated": len(alert_dicts),
        "alerts_created": created,
        "alerts_updated": updated,
        "notifications_sent": notify_stats.get("sent", 0),
        "window_hours": since_hours,
    }


__all__ = [
    "Rule",
    "RuleError",
    "load_rules",
    "matches",
    "evaluate_rule",
    "evaluate_rules",
    "persist_alerts",
    "run_detection",
    "RULES_PATH",
]
