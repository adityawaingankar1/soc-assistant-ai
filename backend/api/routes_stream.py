"""
WebSocket streaming for real-time alert analysis updates
+ SSE streaming for live security events (dashboard) with replay
"""
import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.responses import StreamingResponse
from loguru import logger

from backend.database import SessionLocal, User, SystemLog
from backend.utils.audit import write_audit_log
from backend.auth import decode_token, TokenData
from backend.realtime.event_bus import event_bus

router = APIRouter(tags=["Streaming"])

HEARTBEAT_SECONDS = 15
REPLAY_LIMIT = 30


class ConnectionManager:
    """Manages active WebSocket connections."""
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)
        logger.info(f"[WS] Client connected — total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)
        logger.info(f"[WS] Client disconnected — total: {len(self.active)}")

    async def send(self, ws: WebSocket, data: dict):
        try:
            await ws.send_json(data)
        except Exception:
            self.disconnect(ws)

    async def broadcast(self, data: dict):
        for ws in self.active.copy():
            await self.send(ws, data)


manager = ConnectionManager()


def _auth_sse_user(token: str) -> TokenData:
    """
    SSE auth using token query param (EventSource can't send Authorization header).
    Validates:
    - JWT signature/exp
    - user exists
    - is_active
    - not deleted
    """
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    # tolerate accidental "Bearer <token>" in query
    if token.lower().startswith("bearer "):
        token = token.split(" ", 1)[1].strip()

    td = decode_token(token)

    db = SessionLocal()
    try:
        u = db.query(User).filter(User.id == td.user_id).first()
        if (not u) or (not u.is_active) or (getattr(u, "deleted_at", None) is not None):
            raise HTTPException(status_code=401, detail="Account inactive or deleted")
    finally:
        db.close()

    return td


def _load_replay_events(user: TokenData) -> list[dict]:
    """
    Replay the last N audit events so dashboard isn't empty.
    Admin: global logs
    Non-admin: only their own logs
    """
    db = SessionLocal()
    try:
        q = db.query(SystemLog).order_by(SystemLog.created_at.desc())

        if user.role != "admin":
            q = q.filter(SystemLog.user_id == user.user_id)

        logs = q.limit(REPLAY_LIMIT).all()
    finally:
        db.close()

    # Convert logs to SSE event payloads; send oldest->newest
    events = []
    for log in reversed(logs):
        events.append({
            "event_type": log.event_type,
            "user_id": log.user_id,
            "data": log.event_data if isinstance(log.event_data, dict) else {},
            "ts": (log.created_at.isoformat() + "Z") if log.created_at else None
        })
    return events


@router.get("/api/stream/events")
async def sse_events(
    token: str = Query(..., description="JWT access token (EventSource can't send Authorization header)")
):
    """
    SSE endpoint for dashboard live events.

    Behavior:
    - Sends hello event
    - Replays last 30 audit events (admin = all, analyst = own)
    - Streams live events from event_bus
    - Heartbeat every 15s to keep connection alive

    RBAC:
    - Admin: receives all events
    - Non-admin: receives only events where evt.user_id == current user_id
    """
    user = _auth_sse_user(token)
    q = await event_bus.subscribe()

    # Publish a connect event so UI shows something immediately
    await event_bus.publish({
        "event_type": "sse_client_connected",
        "user_id": user.user_id,
        "role": user.role
    })

    replay_events = _load_replay_events(user)

    async def gen():
        try:
            # initial hello
            yield f"event: hello\ndata: {json.dumps({'ok': True, 'role': user.role})}\n\n"

            # replay recent events
            for evt in replay_events:
                # enforce same scoping as live
                if user.role != "admin":
                    if not evt.get("user_id") or evt.get("user_id") != user.user_id:
                        continue
                yield f"event: security_event\ndata: {json.dumps(evt)}\n\n"

            # live events
            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=HEARTBEAT_SECONDS)

                    # Scope non-admin users
                    if user.role != "admin":
                        if not evt.get("user_id") or evt.get("user_id") != user.user_id:
                            continue

                    yield f"event: security_event\ndata: {json.dumps(evt)}\n\n"

                except asyncio.TimeoutError:
                    yield "event: heartbeat\ndata: {}\n\n"

        finally:
            await event_bus.unsubscribe(q)

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
        "Content-Type": "text/event-stream",
    }
    return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


@router.websocket("/ws/analysis/{client_id}")
async def websocket_analysis(ws: WebSocket, client_id: str):
    """
    WebSocket endpoint for streaming analysis progress.
    """
    await manager.connect(ws)

    db = SessionLocal()
    write_audit_log(db, "ws_client_connected", {"client_id": client_id})
    db.close()

    try:
        while True:
            raw = await ws.receive_text()

            try:
                alert_data = json.loads(raw)
            except json.JSONDecodeError:
                await manager.send(ws, {"type": "error", "message": "Invalid JSON payload"})
                continue

            logger.info(f"[WS] Analysis request from {client_id}")

            db = SessionLocal()
            write_audit_log(
                db,
                "ws_analysis_requested",
                {
                    "client_id": client_id,
                    "alert_source": alert_data.get("alert_source"),
                    "severity": alert_data.get("severity"),
                    "affected_asset": alert_data.get("affected_asset")
                }
            )
            db.close()

            steps = [
                (10, "🔀 Router Agent classifying alert severity..."),
                (25, "🔍 Threat intelligence enrichment running..."),
                (45, "📋 Asset lookup and history retrieval..."),
                (60, "📚 RAG knowledge base querying..."),
                (75, "🧠 LLM triage analysis in progress..."),
                (90, "📝 Generating response playbook..."),
            ]

            for percent, message in steps:
                await manager.send(ws, {"type": "step", "message": message, "percent": percent})
                await asyncio.sleep(0.4)

            try:
                from backend.agents.orchestrator import AgentOrchestrator
                import uuid

                orchestrator = AgentOrchestrator()
                alert_data["alert_id"] = str(uuid.uuid4())

                result = await orchestrator.process_alert(alert_data)

                await manager.send(ws, {"type": "result", "percent": 100, "data": result})
                logger.info(f"[WS] Analysis complete for {client_id}")

                db = SessionLocal()
                write_audit_log(
                    db,
                    "ws_analysis_completed",
                    {
                        "client_id": client_id,
                        "alert_id": alert_data.get("alert_id"),
                        "risk_level": result.get("risk_level"),
                        "triage_decision": result.get("triage_decision")
                    }
                )
                db.close()

            except Exception as e:
                logger.error(f"[WS] Analysis error: {e}")
                await manager.send(ws, {"type": "error", "message": str(e)})

                db = SessionLocal()
                write_audit_log(db, "ws_analysis_failed", {"client_id": client_id, "error": str(e)})
                db.close()

    except WebSocketDisconnect:
        manager.disconnect(ws)

        db = SessionLocal()
        write_audit_log(db, "ws_client_disconnected", {"client_id": client_id})
        db.close()