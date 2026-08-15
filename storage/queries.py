"""Analytics queries shared by the API, the reporting pipeline and the CLI tools.

Design note on time bucketing: date truncation is spelled differently in SQLite
(``strftime``) and PostgreSQL (``date_trunc``). Rather than branch on dialect,
the bucketed queries select bare timestamps and aggregate in Python. At
dashboard volumes (millions of rows is fine; billions is not) the difference is
noise, and it keeps one code path correct on both engines.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session as OrmSession

from storage.models import (
    Alert,
    AlertStatus,
    Attacker,
    Event,
    EventType,
    Session,
    Severity,
    ensure_utc,
    utcnow,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

BUCKETS: dict[str, dt.timedelta] = {
    "1m": dt.timedelta(minutes=1),
    "5m": dt.timedelta(minutes=5),
    "15m": dt.timedelta(minutes=15),
    "1h": dt.timedelta(hours=1),
    "6h": dt.timedelta(hours=6),
    "1d": dt.timedelta(days=1),
}


def _floor(ts: dt.datetime, delta: dt.timedelta) -> dt.datetime:
    """Floor a timestamp to the nearest multiple of ``delta`` since the epoch."""
    epoch = dt.datetime(1970, 1, 1, tzinfo=dt.UTC)
    ts = ensure_utc(ts)
    n = int((ts - epoch) / delta)
    return epoch + n * delta


def _since(hours: float | None) -> dt.datetime | None:
    if hours is None:
        return None
    return utcnow() - dt.timedelta(hours=hours)


# --------------------------------------------------------------------------- #
# Event listing
# --------------------------------------------------------------------------- #


def list_events(
    db: OrmSession,
    *,
    limit: int = 100,
    offset: int = 0,
    service: str | None = None,
    event_type: str | None = None,
    src_ip: str | None = None,
    country: str | None = None,
    username: str | None = None,
    min_severity: str | None = None,
    session_id: str | None = None,
    search: str | None = None,
    since_hours: float | None = None,
    order: str = "desc",
) -> tuple[list[Event], int]:
    """Return ``(events, total_matching)`` for the given filters."""
    stmt = select(Event)
    count_stmt = select(func.count()).select_from(Event)

    conditions = []
    if service:
        conditions.append(Event.service == service)
    if event_type:
        conditions.append(Event.event_type == event_type)
    if src_ip:
        conditions.append(Event.src_ip == src_ip)
    if country:
        conditions.append(Event.country == country.upper())
    if username:
        conditions.append(Event.username == username)
    if session_id:
        conditions.append(Event.session_id == session_id)
    if since_hours is not None:
        conditions.append(Event.ts >= _since(since_hours))
    if min_severity:
        allowed = [s.value for s in Severity if s.rank >= Severity(min_severity).rank]
        conditions.append(Event.severity.in_(allowed))
    if search:
        like = f"%{search}%"
        conditions.append(
            Event.command.ilike(like)
            | Event.path.ilike(like)
            | Event.username.ilike(like)
            | Event.user_agent.ilike(like)
        )

    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = db.execute(count_stmt).scalar_one()
    ordering = Event.ts.desc() if order == "desc" else Event.ts.asc()
    stmt = stmt.order_by(ordering, Event.id.desc()).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars()), int(total)


def get_session_with_events(db: OrmSession, session_id: str) -> Session | None:
    return db.get(Session, session_id)


# --------------------------------------------------------------------------- #
# Sessions
# --------------------------------------------------------------------------- #

SESSION_SORT_FIELDS = ("started_at", "event_count", "commands_run", "auth_attempts", "duration_ms")


def list_sessions(
    db: OrmSession,
    *,
    limit: int = 50,
    offset: int = 0,
    service: str | None = None,
    src_ip: str | None = None,
    min_events: int | None = None,
    has_commands: bool = False,
    since_hours: float | None = None,
    sort: str = "started_at",
) -> tuple[list[Session], int]:
    """Return ``(sessions, total_matching)`` for the replay browser.

    ``has_commands`` is the filter that matters in practice: it narrows thousands
    of drive-by connects down to the handful where somebody reached a shell and
    typed — the only ones worth watching back.
    """
    stmt = select(Session)
    count_stmt = select(func.count()).select_from(Session)

    conditions = []
    if service:
        conditions.append(Session.service == service)
    if src_ip:
        conditions.append(Session.src_ip == src_ip)
    if min_events is not None:
        conditions.append(Session.event_count >= min_events)
    if has_commands:
        conditions.append(Session.commands_run > 0)
    if since_hours is not None:
        conditions.append(Session.started_at >= _since(since_hours))

    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    sort_col = {
        "started_at": Session.started_at,
        "event_count": Session.event_count,
        "commands_run": Session.commands_run,
        "auth_attempts": Session.auth_attempts,
        "duration_ms": Session.duration_ms,
    }.get(sort, Session.started_at)

    total = db.execute(count_stmt).scalar_one()
    # started_at breaks ties so paging is stable when the sort column repeats
    # (it repeats constantly — most sessions run the same handful of commands).
    stmt = stmt.order_by(sort_col.desc(), Session.started_at.desc()).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars()), int(total)


def sessions_geo(db: OrmSession, session_ids: Iterable[str]) -> dict[str, dict[str, Any]]:
    """Geo/ASN per session, derived from that session's events.

    The sensor writes ``sessions`` rows before enrichment runs, so the columns on
    ``Session`` itself are usually empty. Events carry the enrichment, so read it
    back from there — one grouped query rather than one lookup per row.
    """
    ids = [sid for sid in session_ids if sid]
    if not ids:
        return {}
    stmt = (
        select(
            Event.session_id,
            func.max(Event.country),
            func.max(Event.country_name),
            func.max(Event.asn),
            func.max(Event.as_org),
        )
        .where(Event.session_id.in_(ids))
        .group_by(Event.session_id)
    )
    return {
        sid: {"country": country, "country_name": name, "asn": asn, "as_org": org}
        for sid, country, name, asn, org in db.execute(stmt)
    }


# --------------------------------------------------------------------------- #
# Summary statistics
# --------------------------------------------------------------------------- #


def summary_stats(db: OrmSession, since_hours: float | None = 24) -> dict[str, Any]:
    """Headline counters for the overview page."""
    since = _since(since_hours)

    def scoped(stmt):
        return stmt.where(Event.ts >= since) if since else stmt

    total_events = db.execute(scoped(select(func.count()).select_from(Event))).scalar_one()
    unique_ips = db.execute(
        scoped(select(func.count(distinct(Event.src_ip))).select_from(Event))
    ).scalar_one()
    unique_countries = db.execute(
        scoped(select(func.count(distinct(Event.country))).select_from(Event))
    ).scalar_one()
    auth_attempts = db.execute(
        scoped(select(func.count()).select_from(Event)).where(
            Event.event_type == EventType.AUTH_ATTEMPT.value
        )
    ).scalar_one()
    commands = db.execute(
        scoped(select(func.count()).select_from(Event)).where(
            Event.event_type == EventType.COMMAND.value
        )
    ).scalar_one()
    unique_creds = db.execute(
        scoped(
            select(
                func.count(
                    distinct(
                        func.coalesce(Event.username, "") + ":" + func.coalesce(Event.password, "")
                    )
                )
            ).select_from(Event)
        ).where(Event.event_type == EventType.AUTH_ATTEMPT.value)
    ).scalar_one()

    session_stmt = select(func.count()).select_from(Session)
    if since:
        session_stmt = session_stmt.where(Session.started_at >= since)
    sessions = db.execute(session_stmt).scalar_one()

    open_alerts = db.execute(
        select(func.count()).select_from(Alert).where(Alert.status == AlertStatus.NEW.value)
    ).scalar_one()
    critical_alerts = db.execute(
        select(func.count())
        .select_from(Alert)
        .where(Alert.status == AlertStatus.NEW.value)
        .where(Alert.severity.in_([Severity.HIGH.value, Severity.CRITICAL.value]))
    ).scalar_one()

    return {
        "window_hours": since_hours,
        "total_events": int(total_events),
        "unique_attackers": int(unique_ips),
        "unique_countries": int(unique_countries),
        "sessions": int(sessions),
        "auth_attempts": int(auth_attempts),
        "unique_credential_pairs": int(unique_creds),
        "commands_run": int(commands),
        "open_alerts": int(open_alerts),
        "critical_alerts": int(critical_alerts),
        "generated_at": utcnow().isoformat(),
    }


def events_timeseries(
    db: OrmSession,
    *,
    since_hours: float = 24,
    bucket: str = "1h",
    by: str = "service",
) -> dict[str, Any]:
    """Bucketed event counts, split by ``service``, ``severity`` or nothing.

    Empty buckets are filled with zeros so the chart draws a continuous line
    instead of connecting across gaps, which would understate quiet periods.
    """
    if bucket not in BUCKETS:
        raise ValueError(f"unknown bucket {bucket!r}; expected one of {sorted(BUCKETS)}")
    delta = BUCKETS[bucket]
    since = _since(since_hours)

    dimension = {
        "service": Event.service,
        "severity": Event.severity,
        "event_type": Event.event_type,
        "none": None,
    }.get(by)
    if by != "none" and dimension is None:
        raise ValueError(f"cannot split by {by!r}")

    cols = [Event.ts] + ([dimension] if dimension is not None else [])
    stmt = select(*cols)
    if since:
        stmt = stmt.where(Event.ts >= since)

    counts: dict[dt.datetime, Counter] = defaultdict(Counter)
    for row in db.execute(stmt):
        key = _floor(row[0], delta)
        series = row[1] if dimension is not None else "events"
        counts[key][series or "unknown"] += 1

    start = _floor(since or (min(counts) if counts else utcnow()), delta)
    end = _floor(utcnow(), delta)
    series_names = sorted({name for c in counts.values() for name in c})

    points = []
    cursor = start
    while cursor <= end:
        row: dict[str, Any] = {"ts": cursor.isoformat()}
        bucket_counts = counts.get(cursor, Counter())
        for name in series_names:
            row[name] = bucket_counts.get(name, 0)
        row["total"] = sum(bucket_counts.values())
        points.append(row)
        cursor += delta

    return {"bucket": bucket, "by": by, "series": series_names, "points": points}


def hour_weekday_heatmap(db: OrmSession, since_hours: float = 24 * 14) -> dict[str, Any]:
    """Counts per (weekday, UTC hour).

    Reveals whether a campaign runs on a human schedule or a cron job — one of
    the more reliable ways to separate hands-on-keyboard from automation.
    """
    since = _since(since_hours)
    stmt = select(Event.ts)
    if since:
        stmt = stmt.where(Event.ts >= since)

    grid = [[0] * 24 for _ in range(7)]
    total = 0
    for (ts,) in db.execute(stmt):
        ts = ensure_utc(ts)
        grid[ts.weekday()][ts.hour] += 1
        total += 1

    return {
        "since_hours": since_hours,
        "total": total,
        "max": max((max(row) for row in grid), default=0),
        "weekdays": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
        "grid": grid,
    }


def _top(
    db: OrmSession,
    column,
    *,
    limit: int,
    since_hours: float | None,
    where=None,
) -> list[dict[str, Any]]:
    stmt = (
        select(column, func.count().label("count"))
        .where(column.is_not(None))
        .where(column != "")
        .group_by(column)
        .order_by(func.count().desc())
        .limit(limit)
    )
    since = _since(since_hours)
    if since:
        stmt = stmt.where(Event.ts >= since)
    if where is not None:
        stmt = stmt.where(where)
    return [{"value": v, "count": int(c)} for v, c in db.execute(stmt)]


def top_usernames(db: OrmSession, limit: int = 20, since_hours: float | None = 24):
    return _top(db, Event.username, limit=limit, since_hours=since_hours)


def top_passwords(db: OrmSession, limit: int = 20, since_hours: float | None = 24):
    return _top(db, Event.password, limit=limit, since_hours=since_hours)


def top_paths(db: OrmSession, limit: int = 20, since_hours: float | None = 24):
    return _top(db, Event.path, limit=limit, since_hours=since_hours)


def top_user_agents(db: OrmSession, limit: int = 20, since_hours: float | None = 24):
    return _top(db, Event.user_agent, limit=limit, since_hours=since_hours)


def top_commands(db: OrmSession, limit: int = 20, since_hours: float | None = 24):
    return _top(db, Event.command, limit=limit, since_hours=since_hours)


def top_countries(db: OrmSession, limit: int = 50, since_hours: float | None = 24):
    """Country counts with the attacker count alongside, for the world map."""
    since = _since(since_hours)
    stmt = (
        select(
            Event.country,
            func.max(Event.country_name),
            func.count().label("events"),
            func.count(distinct(Event.src_ip)).label("attackers"),
        )
        .where(Event.country.is_not(None))
        .group_by(Event.country)
        .order_by(func.count().desc())
        .limit(limit)
    )
    if since:
        stmt = stmt.where(Event.ts >= since)
    return [
        {"country": c, "country_name": n, "events": int(e), "attackers": int(a)}
        for c, n, e, a in db.execute(stmt)
    ]


def top_asns(db: OrmSession, limit: int = 20, since_hours: float | None = 24):
    since = _since(since_hours)
    stmt = (
        select(
            Event.asn,
            func.max(Event.as_org),
            func.count().label("events"),
            func.count(distinct(Event.src_ip)).label("attackers"),
        )
        .where(Event.asn.is_not(None))
        .group_by(Event.asn)
        .order_by(func.count().desc())
        .limit(limit)
    )
    if since:
        stmt = stmt.where(Event.ts >= since)
    return [
        {"asn": a, "as_org": o, "events": int(e), "attackers": int(n)}
        for a, o, e, n in db.execute(stmt)
    ]


def service_breakdown(db: OrmSession, since_hours: float | None = 24):
    since = _since(since_hours)
    stmt = (
        select(
            Event.service,
            func.count().label("events"),
            func.count(distinct(Event.src_ip)).label("attackers"),
        )
        .group_by(Event.service)
        .order_by(func.count().desc())
    )
    if since:
        stmt = stmt.where(Event.ts >= since)
    return [{"service": s, "events": int(e), "attackers": int(a)} for s, e, a in db.execute(stmt)]


def credential_pairs(db: OrmSession, limit: int = 100, since_hours: float | None = 24):
    """Most-tried username/password combinations."""
    since = _since(since_hours)
    stmt = (
        select(Event.username, Event.password, func.count().label("count"))
        .where(Event.event_type == EventType.AUTH_ATTEMPT.value)
        .where(Event.username.is_not(None))
        .group_by(Event.username, Event.password)
        .order_by(func.count().desc())
        .limit(limit)
    )
    if since:
        stmt = stmt.where(Event.ts >= since)
    return [{"username": u, "password": p, "count": int(c)} for u, p, c in db.execute(stmt)]


# --------------------------------------------------------------------------- #
# Attackers
# --------------------------------------------------------------------------- #


def list_attackers(
    db: OrmSession,
    *,
    limit: int = 50,
    offset: int = 0,
    country: str | None = None,
    classification: str | None = None,
    min_score: float | None = None,
    sort: str = "threat_score",
) -> tuple[list[Attacker], int]:
    stmt = select(Attacker)
    count_stmt = select(func.count()).select_from(Attacker)

    conditions = []
    if country:
        conditions.append(Attacker.country == country.upper())
    if classification:
        conditions.append(Attacker.classification == classification)
    if min_score is not None:
        conditions.append(Attacker.threat_score >= min_score)
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    sort_col = {
        "threat_score": Attacker.threat_score,
        "event_count": Attacker.event_count,
        "last_seen": Attacker.last_seen,
        "first_seen": Attacker.first_seen,
        "auth_attempts": Attacker.auth_attempts,
    }.get(sort, Attacker.threat_score)

    total = db.execute(count_stmt).scalar_one()
    stmt = stmt.order_by(sort_col.desc()).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars()), int(total)


def get_attacker(db: OrmSession, src_ip: str) -> Attacker | None:
    return db.get(Attacker, src_ip)


def attacker_sessions(db: OrmSession, src_ip: str, limit: int = 50) -> list[Session]:
    stmt = (
        select(Session)
        .where(Session.src_ip == src_ip)
        .order_by(Session.started_at.desc())
        .limit(limit)
    )
    return list(db.execute(stmt).scalars())


def rebuild_attackers(db: OrmSession, src_ips: Iterable[str] | None = None) -> int:
    """Recompute the ``attackers`` aggregate from raw events.

    Pass ``src_ips`` to refresh only those rows (the incremental path used after
    a pipeline run); omit it to rebuild everything.
    """
    from pipeline.detection.scoring import score_attacker  # local: avoids import cycle

    if src_ips is None:
        ips = [r[0] for r in db.execute(select(distinct(Event.src_ip)))]
    else:
        ips = list(dict.fromkeys(src_ips))

    updated = 0
    for ip in ips:
        events = list(db.execute(select(Event).where(Event.src_ip == ip)).scalars())
        if not events:
            continue

        usernames = Counter(e.username for e in events if e.username)
        passwords = Counter(e.password for e in events if e.password)
        paths = Counter(e.path for e in events if e.path)
        services = sorted({e.service for e in events})
        session_ids = {e.session_id for e in events if e.session_id}

        geo = next((e for e in events if e.country), None)
        asn_evt = next((e for e in events if e.asn), None)

        row = db.get(Attacker, ip) or Attacker(src_ip=ip)
        row.first_seen = min(ensure_utc(e.ts) for e in events)
        row.last_seen = max(ensure_utc(e.ts) for e in events)
        row.event_count = len(events)
        row.session_count = len(session_ids)
        row.auth_attempts = sum(1 for e in events if e.event_type == EventType.AUTH_ATTEMPT.value)
        row.commands_run = sum(1 for e in events if e.event_type == EventType.COMMAND.value)
        row.distinct_usernames = len(usernames)
        row.distinct_passwords = len(passwords)
        row.services = services
        row.top_usernames = [u for u, _ in usernames.most_common(10)]
        row.top_passwords = [p for p, _ in passwords.most_common(10)]
        row.top_paths = [p for p, _ in paths.most_common(10)]

        if geo is not None:
            row.country = geo.country
            row.country_name = geo.country_name
            row.latitude = geo.latitude
            row.longitude = geo.longitude
        if asn_evt is not None:
            row.asn = asn_evt.asn
            row.as_org = asn_evt.as_org

        score, classification, tags = score_attacker(row, events)
        row.threat_score = score
        row.classification = classification
        row.tags = tags
        row.updated_at = utcnow()

        db.add(row)
        updated += 1

    db.flush()
    return updated


# --------------------------------------------------------------------------- #
# Alerts
# --------------------------------------------------------------------------- #


def list_alerts(
    db: OrmSession,
    *,
    limit: int = 100,
    offset: int = 0,
    status: str | None = None,
    severity: str | None = None,
    rule_id: str | None = None,
    src_ip: str | None = None,
    since_hours: float | None = None,
) -> tuple[list[Alert], int]:
    stmt = select(Alert)
    count_stmt = select(func.count()).select_from(Alert)

    conditions = []
    if status:
        conditions.append(Alert.status == status)
    if severity:
        allowed = [s.value for s in Severity if s.rank >= Severity(severity).rank]
        conditions.append(Alert.severity.in_(allowed))
    if rule_id:
        conditions.append(Alert.rule_id == rule_id)
    if src_ip:
        conditions.append(Alert.src_ip == src_ip)
    if since_hours is not None:
        conditions.append(Alert.last_seen >= _since(since_hours))
    for cond in conditions:
        stmt = stmt.where(cond)
        count_stmt = count_stmt.where(cond)

    total = db.execute(count_stmt).scalar_one()
    stmt = stmt.order_by(Alert.last_seen.desc()).limit(limit).offset(offset)
    return list(db.execute(stmt).scalars()), int(total)


def set_alert_status(
    db: OrmSession, alert_id: str, status: str, notes: str | None = None
) -> Alert | None:
    alert = db.execute(select(Alert).where(Alert.alert_id == alert_id)).scalar_one_or_none()
    if alert is None:
        return None
    alert.status = AlertStatus(status).value
    if notes is not None:
        alert.notes = notes
    db.add(alert)
    db.flush()
    return alert


def alert_counts_by_rule(db: OrmSession, since_hours: float | None = 24):
    stmt = (
        select(Alert.rule_id, func.max(Alert.rule_name), func.sum(Alert.hit_count))
        .group_by(Alert.rule_id)
        .order_by(func.sum(Alert.hit_count).desc())
    )
    since = _since(since_hours)
    if since:
        stmt = stmt.where(Alert.last_seen >= since)
    return [{"rule_id": r, "rule_name": n, "hits": int(h or 0)} for r, n, h in db.execute(stmt)]


__all__ = [
    "list_events",
    "summary_stats",
    "events_timeseries",
    "hour_weekday_heatmap",
    "top_usernames",
    "top_passwords",
    "top_paths",
    "top_commands",
    "top_user_agents",
    "top_countries",
    "top_asns",
    "service_breakdown",
    "credential_pairs",
    "list_attackers",
    "get_attacker",
    "attacker_sessions",
    "rebuild_attackers",
    "list_alerts",
    "set_alert_status",
    "alert_counts_by_rule",
    "get_session_with_events",
    "list_sessions",
    "sessions_geo",
    "SESSION_SORT_FIELDS",
    "BUCKETS",
]
