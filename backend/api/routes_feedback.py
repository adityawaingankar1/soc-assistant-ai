from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
from backend.database import get_db, Feedback, Alert
from backend.auth import TokenData, require_role
from backend.utils.audit import write_audit_log

router = APIRouter(prefix="/api", tags=["Feedback"])

ALLOWED_VERDICTS = {"tp", "fp", "benign", "unknown"}


class FeedbackRequest(BaseModel):
    alert_id: str = Field(..., min_length=6)
    verdict: str = Field(..., description="tp|fp|benign|unknown")
    incident_type: Optional[str] = None
    notes: Optional[str] = None


@router.post("/feedback")
def submit_feedback(
    body: FeedbackRequest,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db)
):
    verdict = (body.verdict or "").strip().lower()
    if verdict not in ALLOWED_VERDICTS:
        raise HTTPException(status_code=422, detail=f"Invalid verdict. Must be one of: {sorted(ALLOWED_VERDICTS)}")

    alert = db.query(Alert).filter(Alert.id == body.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Analysts can only submit feedback for alerts they created (admin can for all)
    if current_user.role != "admin" and alert.created_by != current_user.user_id:
        raise HTTPException(status_code=403, detail="You are not authorized to submit feedback for this alert.")

    fb = Feedback(
        alert_id=body.alert_id,
        incident_type=(body.incident_type or "").strip().upper() or None,
        verdict=verdict,
        notes=(body.notes or "").strip() or None,
        created_by_user_id=current_user.user_id
    )
    db.add(fb)
    db.commit()

    write_audit_log(
        db,
        "feedback_submitted",
        {
            "alert_id": body.alert_id,
            "verdict": verdict,
            "incident_type": fb.incident_type
        },
        user_id=current_user.user_id
    )

    return {"success": True, "feedback_id": fb.id}


@router.get("/feedback")
def list_feedback(
    limit: int = Query(100, ge=1, le=500),
    incident_type: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db)
):
    q = db.query(Feedback).order_by(Feedback.created_at.desc())

    if current_user.role != "admin":
        q = q.filter(Feedback.created_by_user_id == current_user.user_id)

    if incident_type:
        q = q.filter(Feedback.incident_type == incident_type.strip().upper())
    if verdict:
        q = q.filter(Feedback.verdict == verdict.strip().lower())

    rows = q.limit(limit).all()
    return {
        "total": len(rows),
        "feedback": [
            {
                "id": r.id,
                "alert_id": r.alert_id,
                "incident_type": r.incident_type,
                "verdict": r.verdict,
                "notes": r.notes,
                "created_by_user_id": r.created_by_user_id,
                "created_at": r.created_at.isoformat() if r.created_at else None
            } for r in rows
        ]
    }