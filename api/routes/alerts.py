"""Alert endpoints — the triage queue and the rules behind it."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session as OrmSession

from api.schemas import AlertOut, AlertStatusUpdate, Message, Page, RuleOut
from storage import queries
from storage.db import get_db
from storage.models import Severity

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=Page[AlertOut], summary="List alerts")
def list_alerts(
    db: OrmSession = Depends(get_db),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="new | acknowledged | closed"),
    severity: Optional[str] = Query(None, description="minimum severity"),
    rule_id: Optional[str] = Query(None),
    src_ip: Optional[str] = Query(None),
    since_hours: Optional[float] = Query(None, gt=0, le=24 * 365),
) -> Page[AlertOut]:
    if status and status not in ("new", "acknowledged", "closed"):
        raise HTTPException(400, f"unknown status {status!r}")
    if severity and severity not in {s.value for s in Severity}:
        raise HTTPException(400, f"unknown severity {severity!r}")

    rows, total = queries.list_alerts(
        db,
        limit=limit,
        offset=offset,
        status=status,
        severity=severity,
        rule_id=rule_id,
        src_ip=src_ip,
        since_hours=since_hours,
    )
    return Page[AlertOut](
        items=[AlertOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/rules", response_model=list[RuleOut], summary="List detection rules")
def list_rules() -> list[RuleOut]:
    """The loaded rule definitions.

    Served so the dashboard can show *why* a rule fired and what its threshold
    is, without the analyst having to open the YAML.
    """
    from pipeline.detection.rules import load_rules

    return [
        RuleOut(
            id=rule.id,
            name=rule.name,
            severity=rule.severity,
            type=rule.type,
            description=rule.description,
            enabled=rule.enabled,
            window_minutes=rule.window_minutes,
            group_by=rule.group_by,
            threshold=rule.threshold,
            distinct_field=rule.distinct_field,
            mitre=rule.mitre,
        )
        for rule in load_rules()
    ]


@router.get("/by-rule", summary="Alert counts grouped by rule")
def by_rule(
    db: OrmSession = Depends(get_db),
    hours: Optional[float] = Query(24, gt=0, le=24 * 365),
) -> list[dict]:
    return queries.alert_counts_by_rule(db, since_hours=hours)


@router.post("/run", response_model=dict, summary="Run detection now")
def run_now(
    db: OrmSession = Depends(get_db),
    hours: float = Query(24, gt=0, le=24 * 90),
) -> dict:
    """Evaluate every rule over the last ``hours`` and persist the results.

    Exposed so the dashboard has a "re-run detection" button and so a fresh
    import can be scored immediately, rather than waiting for the scheduler.
    """
    from pipeline.detection.rules import run_detection

    result = run_detection(db, since_hours=hours)
    db.commit()
    return result


@router.get("/{alert_id}", response_model=AlertOut, summary="Get one alert")
def get_alert(alert_id: str, db: OrmSession = Depends(get_db)) -> AlertOut:
    from sqlalchemy import select

    from storage.models import Alert

    row = db.execute(select(Alert).where(Alert.alert_id == alert_id)).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, f"no alert {alert_id}")
    return AlertOut.model_validate(row)


@router.patch("/{alert_id}", response_model=AlertOut, summary="Update alert status")
def update_alert(
    alert_id: str,
    payload: AlertStatusUpdate,
    db: OrmSession = Depends(get_db),
) -> AlertOut:
    """Acknowledge or close an alert.

    The only mutating endpoint on observation data, and it only touches triage
    metadata — an alert's evidence is never editable, because an audit trail you
    can rewrite is not an audit trail.
    """
    alert = queries.set_alert_status(db, alert_id, payload.status, payload.notes)
    if alert is None:
        raise HTTPException(404, f"no alert {alert_id}")
    db.commit()
    return AlertOut.model_validate(alert)


__all__ = ["router"]
