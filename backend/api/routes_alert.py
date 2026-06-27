"""
Alert Analysis Routes
Handles: /analyze-alert, /correlate-alerts, /alerts (list + detail)

RBAC:
- Analyze / Correlate: admin + analyst
- List / Detail / Stats: authenticated roles, but scoped by user unless admin
- Delete: admin only
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from datetime import datetime
import uuid
import json
import re

from backend.database import get_db, Alert, AlertResponse, User
from backend.middleware.rate_limit import limiter
from backend.auth import TokenData, require_role
from backend.utils.audit import write_audit_log
from backend.tools.ioc_tool import IOCTool
from backend.tools.tool_registry import ToolRegistry
from loguru import logger

router = APIRouter(prefix="/api", tags=["Alert Analysis"])

ioc_tool = IOCTool()
tool_registry = ToolRegistry()

# Optional calibration (only if you added the model)
try:
    from backend.database import ConfidenceCalibration  # type: ignore
except Exception:
    ConfidenceCalibration = None  # type: ignore


class AlertRequest(BaseModel):
    alert_source: str = Field(..., description="Tool that generated the alert")
    severity: str = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW | INFO")
    affected_asset: str = Field(..., description="Hostname, IP, or asset ID")
    ioc_list: str = Field(..., description="Comma-separated IOCs or JSON array/object string")
    mitre_mapping: Optional[str] = Field(None, description="MITRE ATT&CK technique ID")
    description: str = Field(..., description="Full alert narrative")
    timestamp: Optional[str] = Field(None, description="ISO 8601 event timestamp")
    additional_context: Optional[str] = Field(None, description="Extra context / notes")


class CorrelationRequest(BaseModel):
    alert_ids: List[str] = Field(..., min_length=2, description="List of alert IDs to correlate")


def _validate_severity(severity: str) -> str:
    allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
    upper = severity.upper().strip()
    if upper not in allowed:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity '{severity}'. Must be one of: {sorted(allowed)}",
        )
    return upper


def _store_alert(db: Session, alert_id: str, req: AlertRequest, created_by: str = None) -> Alert:
    alert = Alert(
        id=alert_id,
        alert_source=req.alert_source.strip(),
        severity=_validate_severity(req.severity),
        affected_asset=req.affected_asset.strip(),
        ioc_list=req.ioc_list.strip(),
        mitre_mapping=(req.mitre_mapping or "").strip(),
        raw_alert=req.description.strip(),
        created_by=created_by,
    )
    db.add(alert)
    db.commit()
    return alert


def _store_response(db: Session, alert_id: str, result: dict) -> AlertResponse:
    response = AlertResponse(
        alert_id=alert_id,
        triage_decision=result.get("triage_decision"),
        risk_level=result.get("risk_level"),
        attack_type=result.get("attack_type"),
        explanation=result.get("explanation"),
        recommended_actions=result.get("recommended_actions", []),
        confidence_score=result.get("confidence_score", 0.0),
        source_citations=result.get("source_citations", []),
        follow_up_questions=result.get("follow_up_questions", []),
        enrichment_data=result.get("enrichment_data", {}),
        playbook=result.get("playbook", ""),
    )
    db.add(response)
    db.commit()
    return response


def _scope_alert_query(query, current_user: TokenData):
    if current_user.role == "admin":
        return query
    return query.filter(Alert.created_by == current_user.user_id)


def _user_can_access_alert(alert: Alert, current_user: TokenData) -> bool:
    if current_user.role == "admin":
        return True
    return alert.created_by == current_user.user_id


def _safe_json_loads(s: str) -> Optional[Any]:
    try:
        return json.loads(s)
    except Exception:
        return None


def _as_dict(v: Any) -> Dict[str, Any]:
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            x = json.loads(v)
            return x if isinstance(x, dict) else {}
        except Exception:
            return {}
    return {}


def _extract_router_hint(enrichment_data: Any) -> Optional[Dict[str, Any]]:
    ed = _as_dict(enrichment_data)
    soc = _as_dict(ed.get("soc_artifacts"))
    hint = _as_dict(soc.get("router_hint"))
    if not hint:
        return None

    out = {
        "decision": hint.get("decision"),
        "confidence": hint.get("confidence"),
        "reason": hint.get("reason"),
    }
    if not out["decision"] and out["confidence"] is None and not out["reason"]:
        return None
    return out


def _parse_ioc_input(raw: str) -> List[Any]:
    """
    JSON-first parsing:
    - If raw is JSON array/object string -> parse
    - Else split on comma/newline/semicolon
    """
    if raw is None:
        return []
    s = str(raw).strip()
    if not s:
        return []
    if s.startswith("[") or s.startswith("{"):
        parsed = _safe_json_loads(s)
        if parsed is not None:
            return IOCTool.parse_ioc_list(parsed)
    parts = re.split(r"[,\n;]+", s)
    return [p.strip() for p in parts if p and p.strip()]


@router.post("/analyze-alert")
@limiter.limit("10/minute")
async def analyze_alert(
    request: Request,
    alert_req: AlertRequest,
    background_tasks: BackgroundTasks,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Production pattern:
    - Store alert immediately
    - Normalize + enrich quick IOCs
    - Queue heavy analysis via Celery task
    - Return task_id to UI
    """
    alert_id = str(uuid.uuid4())
    start_time = datetime.utcnow()

    logger.info(
        f"[Alert] New request by '{current_user.username}' — "
        f"id={alert_id[:8]} source='{alert_req.alert_source}' severity={alert_req.severity}"
    )

    try:
        _store_alert(db, alert_id, alert_req, created_by=current_user.user_id)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Alert] DB write failed: {e}")
        raise HTTPException(status_code=500, detail="Failed to store alert in database.")

    # --- Normalization ---
    raw_iocs = _parse_ioc_input(alert_req.ioc_list)
    entities = IOCTool.classify_iocs(raw_iocs)

    enrich_inputs = []
    for e in entities:
        et = e.get("entity_type")
        if et in {"ip", "domain", "url", "hash"} and e.get("normalized"):
            enrich_inputs.append({"indicator": e["normalized"], "type": et})

    ioc_enrichment = []
    try:
        if enrich_inputs:
            ioc_enrichment = ioc_tool.bulk_enrich(enrich_inputs)
    except Exception as e:
        logger.warning(f"[Alert] IOC enrichment failed (non-fatal): {e}")

    alert_data = {
        "alert_id": alert_id,
        "alert_source": alert_req.alert_source,
        "severity": alert_req.severity.upper(),
        "affected_asset": alert_req.affected_asset,
        "ioc_list": alert_req.ioc_list,
        "mitre_mapping": alert_req.mitre_mapping or "",
        "description": alert_req.description,
        "timestamp": alert_req.timestamp or datetime.utcnow().isoformat(),
        "additional_context": alert_req.additional_context or "",
        "parsed_iocs": raw_iocs,
        "entities": entities,
        "ioc_enrichment": ioc_enrichment,
    }

    # =========================================================
    # Queue analysis (do NOT instantiate heavy orchestrator here)
    # Graph ingestion is also done INSIDE the task only.
    # =========================================================
    from backend.tasks.alert_tasks import process_alert_task

    try:
        task = process_alert_task.delay(alert_data, current_user.user_id)

        logger.info(f"[Alert] queued task_id={task.id}")

        # Optional: audit log that the task was queued
        background_tasks.add_task(
            write_audit_log,
            db,
            "alert_analysis_queued",
            {
                "alert_id": alert_id,
                "task_id": task.id,
                "queued_by": current_user.username,
                "role": current_user.role,
                "source": alert_req.alert_source,
                "severity": alert_req.severity,
                "queued_at": datetime.utcnow().isoformat(),
                "elapsed_seconds": round((datetime.utcnow() - start_time).total_seconds(), 2),
            },
            current_user.user_id,
        )

        return {
            "alert_id": alert_id,
            "task_id": task.id,
            "status": "processing",
        }

    except Exception as e:
        logger.exception(f"[Alert] Failed to queue analysis task: {e}")
        raise HTTPException(status_code=503, detail="Failed to queue alert analysis task.")


@router.get("/alerts")
def get_alerts(
    limit: int = 20,
    offset: int = 0,
    severity: Optional[str] = None,
    decision: Optional[str] = None,
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    query = db.query(Alert).order_by(Alert.created_at.desc())
    query = _scope_alert_query(query, current_user)

    if severity:
        query = query.filter(Alert.severity == severity.upper())
    if decision:
        query = (
            query.join(AlertResponse, Alert.id == AlertResponse.alert_id, isouter=True)
            .filter(AlertResponse.triage_decision == decision.lower())
        )

    total = query.count()
    alerts = query.offset(offset).limit(limit).all()

    creator_ids = {a.created_by for a in alerts if a.created_by}
    creators = {}
    if creator_ids:
        users = db.query(User).filter(User.id.in_(list(creator_ids))).all()
        creators = {u.id: u for u in users}

    rows = []
    for alert in alerts:
        resp = db.query(AlertResponse).filter(AlertResponse.alert_id == alert.id).first()
        u = creators.get(alert.created_by) if alert.created_by else None
        router_hint = _extract_router_hint(resp.enrichment_data) if resp else None

        rows.append(
            {
                "alert": {
                    "id": alert.id,
                    "source": alert.alert_source,
                    "severity": alert.severity,
                    "asset": alert.affected_asset,
                    "ioc_list": alert.ioc_list,
                    "mitre": alert.mitre_mapping,
                    "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    "created_by_user_id": alert.created_by,
                    "created_by_display_id": getattr(u, "display_id", None) if u else None,
                    "created_by_username": getattr(u, "username", None) if u else None,
                },
                "response": (
                    {
                        "triage_decision": resp.triage_decision,
                        "risk_level": resp.risk_level,
                        "attack_type": resp.attack_type,
                        "confidence_score": resp.confidence_score,
                        "router_hint": (
                            {
                                "decision": (router_hint or {}).get("decision"),
                                "confidence": (router_hint or {}).get("confidence"),
                            }
                            if router_hint
                            else None
                        ),
                    }
                    if resp
                    else None
                ),
            }
        )

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "filters": {"severity": severity, "decision": decision},
        "data": rows,
    }


@router.get("/alerts/{alert_id}")
def get_alert_detail(
    alert_id: str,
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")

    if not _user_can_access_alert(alert, current_user):
        raise HTTPException(status_code=403, detail="You are not authorized to view this alert.")

    resp = db.query(AlertResponse).filter(AlertResponse.alert_id == alert_id).first()
    u = db.query(User).filter(User.id == alert.created_by).first() if alert.created_by else None
    router_hint = _extract_router_hint(resp.enrichment_data) if resp else None

    return {
        "alert": {
            "id": alert.id,
            "source": alert.alert_source,
            "severity": alert.severity,
            "asset": alert.affected_asset,
            "ioc_list": alert.ioc_list,
            "mitre_mapping": alert.mitre_mapping,
            "description": alert.raw_alert,
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "created_by_user_id": alert.created_by,
            "created_by_display_id": u.display_id if u else None,
            "created_by_username": u.username if u else None,
        },
        "analysis": (
            {
                "triage_decision": resp.triage_decision,
                "risk_level": resp.risk_level,
                "attack_type": resp.attack_type,
                "explanation": resp.explanation,
                "recommended_actions": resp.recommended_actions,
                "confidence_score": resp.confidence_score,
                "router_hint": router_hint,
                "source_citations": resp.source_citations,
                "follow_up_questions": resp.follow_up_questions,
                "enrichment_data": resp.enrichment_data,
                "playbook": resp.playbook,
            }
            if resp
            else None
        ),
    }