# backend/api/routes_stream_events.py
import asyncio
import json
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import Optional

from backend.auth import decode_token, TokenData
from backend.database import get_db, User
from backend.realtime.event_bus import event_bus

router = APIRouter(prefix="/api/stream", tags=["Streaming"])

HEARTBEAT_SECONDS = 15


def _auth_from_token_query(
    token: str,
    db: Session
) -> TokenData:
    """
    SSE auth: token in query param.
    Validates:
    - JWT signature/expiry
    - user exists
    - user is_active
    - not deleted
    """
    if not token:
        raise HTTPException(status_code=401, detail="Missing token")

    td = decode_token(token)

    user = db.query(User).filter(User.id == td.user_id).first()
    if (not user) or (not user.is_active) or (getattr(user, "deleted_at", None) is not None):
        raise HTTPException(status_code=401, detail="Account inactive or deleted")

    return td


@router.get("/events")
async def stream_events(
    token: str = Query(..., description="JWT access token (EventSource can't send headers)"),
    db: Session = Depends(get_db)
):
    user = _auth_from_token_query(token, db)

    # RBAC: allow all authenticated roles to receive events
    # (Admin sees all; non-admin can still receive events but you might want to scope them later)
    # If you want strict scoping, we can filter by user_id.
    q = await event_bus.subscribe()

    async def gen():
        try:
            # Initial hello event
            yield f"event: hello\ndata: {json.dumps({'ok': True, 'role': user.role})}\n\n"

            last_heartbeat = asyncio.get_event_loop().time()

            while True:
                try:
                    evt = await asyncio.wait_for(q.get(), timeout=HEARTBEAT_SECONDS)
                    # Optional scoping: if not admin, only forward own events
                    if user.role != "admin":
                        if evt.get("user_id") and evt.get("user_id") != user.user_id:
                            continue

                    yield f"event: security_event\ndata: {json.dumps(evt)}\n\n"
                except asyncio.TimeoutError:
                    # heartbeat to keep connection alive
                    now = asyncio.get_event_loop().time()
                    if now - last_heartbeat >= HEARTBEAT_SECONDS:
                        yield "event: heartbeat\ndata: {}\n\n"
                        last_heartbeat = now
        finally:
            await event_bus.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream")