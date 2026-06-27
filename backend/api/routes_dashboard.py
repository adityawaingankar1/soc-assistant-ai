# backend/api/routes_dashboard.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from typing import Dict, Optional

from backend.database import get_db, Alert, AlertResponse
from backend.auth import TokenData, require_role

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _parse_range(range_str: str) -> timedelta:
    s = (range_str or "24h").strip().lower()
    if s.endswith("h"):
        return timedelta(hours=int(s[:-1]))
    if s.endswith("d"):
        return timedelta(days=int(s[:-1]))
    return timedelta(hours=24)


def _floor_hour(dt: datetime) -> datetime:
    return dt.replace(minute=0, second=0, microsecond=0)


def _scope_alerts(q, user: TokenData):
    if user.role == "admin":
        return q
    return q.filter(Alert.created_by == user.user_id)


@router.get("/overview")
def overview(
    range: str = Query("24h"),
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db)
):
    delta = _parse_range(range)
    since = datetime.utcnow() - delta

    base = db.query(Alert).filter(Alert.created_at >= since)
    base = _scope_alerts(base, current_user)

    total_alerts = base.count()

    # KPI: severity breakdown
    sev_rows = (
        base.with_entities(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    by_severity = {s: int(c) for s, c in sev_rows}

    # KPI: decision breakdown
    resp_q = (
        db.query(AlertResponse.triage_decision, func.count(AlertResponse.id))
        .join(Alert, Alert.id == AlertResponse.alert_id)
        .filter(Alert.created_at >= since)
    )
    if current_user.role != "admin":
        resp_q = resp_q.filter(Alert.created_by == current_user.user_id)

    decision_rows = resp_q.group_by(AlertResponse.triage_decision).all()
    by_decision = { (d or "unknown"): int(c) for d, c in decision_rows }

    # Recent analyzed alerts (table to show "results")
    recent_alerts = (
        base.order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )

    recent = []
    for a in recent_alerts:
        r = db.query(AlertResponse).filter(AlertResponse.alert_id == a.id).first()
        recent.append({
            "alert_id": a.id,
            "source": a.alert_source,
            "severity": a.severity,
            "asset": a.affected_asset,
            "mitre": a.mitre_mapping,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "triage_decision": getattr(r, "triage_decision", None) if r else None,
            "risk_level": getattr(r, "risk_level", None) if r else None,
            "confidence_score": getattr(r, "confidence_score", None) if r else None
        })

    return {
        "range": range,
        "scope": "global" if current_user.role == "admin" else "user",
        "total_alerts": total_alerts,
        "by_severity": by_severity,
        "by_decision": by_decision,
        "recent_alerts": recent
    }


@router.get("/timeseries")
def timeseries(
    range: str = Query("24h"),
    interval: str = Query(
        "hour",
        description="hour|day"
    ),
    current_user: TokenData = Depends(
        require_role("admin", "analyst", "viewer")
    ),
    db: Session = Depends(get_db)
):

    delta = _parse_range(range)

    now = datetime.utcnow()

    since = now - delta

    q = db.query(Alert).filter(
        Alert.created_at >= since
    )

    q = _scope_alerts(q, current_user)

    # =====================================================
    # POSTGRESQL-COMPATIBLE BUCKETS
    # =====================================================

    if interval == "day":

        bucket_expr = func.date_trunc(
            "day",
            Alert.created_at
        ).label("bucket")

        start = since.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        end = now.replace(
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )

        step = timedelta(days=1)

        fmt = "%Y-%m-%d"

    else:

        bucket_expr = func.date_trunc(
            "hour",
            Alert.created_at
        ).label("bucket")

        start = _floor_hour(since)

        end = _floor_hour(now)

        step = timedelta(hours=1)

        fmt = "%Y-%m-%d %H:00"

    rows = (

        q.with_entities(
            bucket_expr,
            Alert.severity,
            func.count(Alert.id)
        )

        .group_by(
            bucket_expr,
            Alert.severity
        )

        .order_by(bucket_expr)

        .all()
    )

    # =====================================================
    # BUILD BUCKET MAP
    # =====================================================

    bucket_map: Dict[str, Dict[str, int]] = {}

    for b, sev, cnt in rows:

        if b is None:
            continue

        bucket_key = b.strftime(fmt)

        bucket_map.setdefault(bucket_key, {})

        bucket_map[bucket_key][sev] = int(cnt)

    # =====================================================
    # CONTINUOUS TIMESERIES
    # =====================================================

    series = []

    cur = start

    while cur <= end:

        bucket_key = cur.strftime(fmt)

        entry = {
            "t": bucket_key
        }

        sev_counts = bucket_map.get(
            bucket_key,
            {}
        )

        for sev in SEVERITIES:

            entry[sev] = sev_counts.get(
                sev,
                0
            )

        series.append(entry)

        cur += step

    return {
        "range": range,
        "interval": interval,
        "series": series
    }