from __future__ import annotations

import os
import uuid
from datetime import datetime
from typing import Dict, Any, List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.auth import TokenData, require_role
from backend.database import get_db, Alert, EvidenceArtifact
from backend.tools.ioc_tool import IOCTool
from backend.tools.spl_tool import SplunkSPLTool
from backend.connectors.splunk_connector import SplunkConnector
from backend.analysis.evidence_store import cap_rows, cap_bytes, hash_rows

from backend.graph.neo4j_client import Neo4jClient
from backend.graph.graph_builder import GraphBuilder

router = APIRouter(prefix="/api/investigation", tags=["Investigation"])


def _store_evidence(
    db: Session,
    *,
    alert_id: str,
    connector: str,
    query_name: str,
    query_text: str,
    rows: List[Dict[str, Any]],
    executed_by: str,
) -> EvidenceArtifact:
    capped, w1 = cap_rows(rows)
    capped2, w2 = cap_bytes(capped)
    warnings = w1 + w2
    rh = hash_rows(capped2)

    ev = EvidenceArtifact(
        id=str(uuid.uuid4()),
        alert_id=alert_id,
        connector=connector,
        query_name=query_name,
        query_text=query_text,
        status="truncated" if warnings else "ingested",
        executed_by=executed_by,
        executed_at=datetime.utcnow(),
        row_count=len(capped2),
        rows_json=capped2,
        warnings=warnings,
        rows_hash=rh,
        created_at=datetime.utcnow(),
    )
    db.add(ev)
    db.commit()
    return ev


@router.post("/{alert_id}/generate-spl")
def generate_spl_bundle(
    alert_id: str,
    body: Dict[str, Any],
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Generates Splunk SPL queries for the stored alert.
    body: {"incident_type":"RANSOMWARE", "time_window_hours":24}
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    incident_type = (body.get("incident_type") or "INVESTIGATE").upper()
    time_window_hours = int(body.get("time_window_hours") or 24)

    raw_iocs = IOCTool.parse_ioc_list(alert.ioc_list or "")
    entities = IOCTool.classify_iocs(raw_iocs)

    spl = SplunkSPLTool().generate(
        incident_type=incident_type,
        affected_asset=alert.affected_asset or "",
        entities=entities,
        time_window_hours=time_window_hours,
    )

    return {"success": True, "alert_id": alert_id, "splunk": spl, "entities": entities}


@router.post("/{alert_id}/execute-spl")
def execute_spl_bundle(
    alert_id: str,
    body: Dict[str, Any],
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Execute a Splunk SPL bundle (queries) and store evidence artifacts in Postgres.
    body:
      {
        "queries": [{"name":"...", "query":"search ..."}],
        "time_window_hours": 24
      }
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    queries = body.get("queries") or []
    time_window_hours = int(body.get("time_window_hours") or 24)

    if not isinstance(queries, list) or not queries:
        raise HTTPException(status_code=422, detail="queries must be a non-empty list")

    splunk = SplunkConnector()

    created = []
    for q in queries[:10]:
        name = (q.get("name") or "Splunk Query").strip()
        query = (q.get("query") or "").strip()
        if not query:
            continue

        res = splunk.execute_search(query, earliest_time=f"-{time_window_hours}h", latest_time="now")
        rows = res.get("rows") or []

        ev = _store_evidence(
            db,
            alert_id=alert_id,
            connector="splunk",
            query_name=name,
            query_text=query,
            rows=rows,
            executed_by=current_user.user_id,
        )
        created.append({"evidence_id": ev.id, "query_name": name, "row_count": ev.row_count, "status": ev.status})

    # Update Neo4j graph (alert + entities)
    try:
        raw_iocs = IOCTool.parse_ioc_list(alert.ioc_list or "")
        entities = IOCTool.classify_iocs(raw_iocs)

        neo = Neo4jClient()
        gb = GraphBuilder(neo)
        gb.upsert_alert(alert_id, alert.affected_asset or "", alert.alert_source or "", alert.severity or "")
        gb.add_entities(alert_id, entities)
        neo.close()
    except Exception:
        pass

    return {"success": True, "alert_id": alert_id, "created": created, "time_window_hours": time_window_hours}


@router.get("/{alert_id}/evidence")
def list_evidence(
    alert_id: str,
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(EvidenceArtifact)
        .filter(EvidenceArtifact.alert_id == alert_id)
        .order_by(EvidenceArtifact.created_at.desc())
        .all()
    )

    return {
        "success": True,
        "alert_id": alert_id,
        "total": len(rows),
        "data": [
            {
                "id": r.id,
                "connector": r.connector,
                "query_name": r.query_name,
                "status": r.status,
                "row_count": r.row_count,
                "warnings": r.warnings,
                "rows_hash": r.rows_hash,
                "executed_at": r.executed_at.isoformat() if r.executed_at else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }