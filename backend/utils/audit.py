# backend/utils/audit.py
from __future__ import annotations
from typing import Optional, Dict, Any, List
from loguru import logger
from sqlalchemy.orm import Session
from backend.config import get_settings
from backend.database import SystemLog, SessionLocal
from backend.utils.pii import redact_pii_keys
from backend.realtime.event_bus import publish_threadsafe


def _summarize_for_stream(event_type: str, data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}

    mapping: Dict[str, List[str]] = {
        # Alerts
        "alert_analyzed": [
            "alert_id", "source", "severity",
            "triage_decision", "risk_level",
            "confidence_score", "processing_time_seconds"
        ],
        "alert_deleted": ["alert_id"],

        # Chat
        "chat_message_processed": ["session_id", "rag_used", "general_question", "history_length"],
        "chat_history_cleared": ["session_id", "messages_deleted"],
        "chat_sessions_listed": ["limit"],

        # KB
        "kb_document_uploaded": ["filename", "doc_type", "chunks_ingested", "file_size_bytes"],
        "kb_document_deleted": ["filename", "doc_id", "deleted_chunks"],
        "kb_reset": ["success"],
        "kb_reloaded": ["chunks_loaded"],

        # Websocket analysis
        "ws_analysis_completed": ["client_id", "alert_id", "risk_level", "triage_decision"],
        "ws_analysis_failed": ["client_id"],

        # NEW: KQL generation
        "kql_queries_generated": ["alert_id", "incident_type", "query_count"],

        # (Optional, if you add these routes later)
        "playbooks_reloaded": ["count", "profile"],
        "feedback_submitted": ["alert_id", "verdict", "incident_type"],
        "calibration_recomputed": ["updated", "min_samples"],
    }

    keys = mapping.get(event_type, [])
    if not keys:
        return {}

    out: Dict[str, Any] = {}
    for k in keys:
        if k in data:
            out[k] = data.get(k)
    return out


def write_audit_log(
    db: Optional[Session],
    event_type: str,
    event_data: Dict[str, Any],
    user_id: Optional[str] = None
) -> bool:
    """
    Writes audit log to DB and publishes SSE event reliably.
    Never raises.
    """
    settings = get_settings()

    safe_data = event_data or {}
    if settings.audit_strip_pii_keys and isinstance(safe_data, (dict, list)):
        safe_data = redact_pii_keys(safe_data, placeholder=settings.audit_pii_placeholder)

    summary = _summarize_for_stream(event_type, safe_data)

    def _write(sess: Session) -> bool:
        record = SystemLog(
            event_type=event_type,
            event_data=safe_data,
            user_id=user_id
        )
        sess.add(record)
        sess.commit()

        publish_threadsafe({
            "event_type": event_type,
            "user_id": user_id,
            "data": summary
        })
        return True

    try:
        if db is None:
            raise RuntimeError("No DB session provided")
        ok = _write(db)
        logger.info(f"[Audit] {event_type}")
        return ok
    except Exception as e:
        try:
            fallback = SessionLocal()
            ok = _write(fallback)
            fallback.close()
            logger.info(f"[Audit] {event_type} (fallback session)")
            return ok
        except Exception as e2:
            logger.error(f"[Audit] Failed to write event '{event_type}': {e} | fallback failed: {e2}")
            return False