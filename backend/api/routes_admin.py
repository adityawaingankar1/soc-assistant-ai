from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from typing import Optional, Any, Dict
import copy
from backend.database import get_db, SystemLog, User, Feedback, ConfidenceCalibration
from backend.auth import TokenData, require_role
from backend.utils.audit import write_audit_log

router = APIRouter(prefix="/api/admin", tags=["Admin"])


def _mask(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 2:
        return value[0] + "*"
    return value[:2] + "*" * (len(value) - 2)


@router.get("/audit-logs")
def get_audit_logs(
    limit: int = Query(100, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    user_display_id: Optional[str] = Query(None),
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    query = db.query(SystemLog).order_by(SystemLog.created_at.desc())
    if event_type:
        query = query.filter(SystemLog.event_type == event_type)

    if user_display_id and not user_id:
        u = db.query(User).filter(User.display_id == user_display_id).first()
        if u:
            user_id = u.id
        else:
            return {
                "total": 0,
                "limit": limit,
                "filters": {"event_type": event_type, "user_id": None, "user_display_id": user_display_id},
                "logs": []
            }

    if user_id:
        query = query.filter(SystemLog.user_id == user_id)

    logs = query.limit(limit).all()
    actor_ids = {l.user_id for l in logs if l.user_id}
    actors = {}
    if actor_ids:
        users = db.query(User).filter(User.id.in_(list(actor_ids))).all()
        actors = {u.id: u for u in users}

    def _compute_actor_email(user: User) -> Optional[str]:
        if not user:
            return None
        if getattr(user, "purged_at", None) is not None:
            return None
        return (getattr(user, "original_email", None) or user.email)

    out_logs = []
    for log in logs:
        u = actors.get(log.user_id) if log.user_id else None
        actor_email = _compute_actor_email(u) if u else None
        actor = None
        if u:
            actor = {
                "user_id": u.id,
                "display_id": getattr(u, "display_id", None),
                "username": u.username,
                "email": actor_email,
                "is_deleted": bool(getattr(u, "deleted_at", None)),
                "is_purged": bool(getattr(u, "purged_at", None)),
                "original_username_masked": _mask(getattr(u, "original_username", None)),
            }

        event_data_out = log.event_data
        if isinstance(event_data_out, dict):
            event_data_out = copy.deepcopy(event_data_out)
            event_data_out["actor_email"] = actor_email

        out_logs.append({
            "id": log.id,
            "event_type": log.event_type,
            "event_data": event_data_out,
            "user_id": log.user_id,
            "actor": actor,
            "created_at": log.created_at.isoformat() if log.created_at else None
        })

    return {
        "total": len(out_logs),
        "limit": limit,
        "filters": {"event_type": event_type, "user_id": user_id, "user_display_id": user_display_id},
        "logs": out_logs
    }


# ---------- NEW: Calibration endpoints ----------

def _bounded_multiplier(tp: int, fp: int) -> float:
    """
    Bounded tuning:
    - Base multiplier 1.0
    - If precision low -> reduce (down to 0.90)
    - If precision high -> increase (up to 1.05)
    """
    total = tp + fp
    if total <= 0:
        return 1.0
    precision = tp / total
    if precision < 0.60:
        return 0.90
    if precision > 0.85:
        return 1.05
    return 1.0


@router.get("/calibration")
def get_calibration(
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    rows = db.query(ConfidenceCalibration).order_by(ConfidenceCalibration.incident_type.asc()).all()
    return {
        "total": len(rows),
        "calibrations": [
            {
                "incident_type": r.incident_type,
                "final_multiplier": r.final_multiplier,
                "sample_count": r.sample_count,
                "tp_count": r.tp_count,
                "fp_count": r.fp_count,
                "updated_at": r.updated_at.isoformat() if r.updated_at else None
            } for r in rows
        ]
    }


@router.post("/calibration/recompute")
def recompute_calibration(
    min_samples: int = Query(20, ge=5, le=500),
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    # Aggregate feedback by incident_type
    rows = db.query(Feedback).all()
    buckets: Dict[str, Dict[str, int]] = {}

    for f in rows:
        it = (f.incident_type or "UNKNOWN").upper()
        if it not in buckets:
            buckets[it] = {"tp": 0, "fp": 0}
        if f.verdict == "tp":
            buckets[it]["tp"] += 1
        elif f.verdict == "fp":
            buckets[it]["fp"] += 1

    updated = 0
    for incident_type, counts in buckets.items():
        tp = counts["tp"]
        fp = counts["fp"]
        total = tp + fp
        if total < min_samples:
            continue

        mult = _bounded_multiplier(tp, fp)

        existing = db.query(ConfidenceCalibration).filter(ConfidenceCalibration.incident_type == incident_type).first()
        if existing:
            existing.final_multiplier = mult
            existing.sample_count = total
            existing.tp_count = tp
            existing.fp_count = fp
        else:
            db.add(ConfidenceCalibration(
                incident_type=incident_type,
                final_multiplier=mult,
                sample_count=total,
                tp_count=tp,
                fp_count=fp
            ))
        updated += 1

    db.commit()

    write_audit_log(
        db,
        "calibration_recomputed",
        {"updated": updated, "min_samples": min_samples},
        user_id=current_user.user_id
    )

    return {"success": True, "updated": updated, "min_samples": min_samples}