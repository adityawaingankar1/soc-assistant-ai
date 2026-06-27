# backend/api/routes_chat.py
"""
Chat Routes

Features:
- Blocking /api/chat for backward compatibility
- Streaming /api/chat/stream for fast SOC Chat UX
- RBAC for admin + analyst
- User-scoped chat sessions
- Markdown response sanitization
- Faster RAG policy for general questions
"""

from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, List

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session
from loguru import logger

from backend.database import get_db, SessionLocal, ChatSession, User
from backend.llm.nvidia_client import nvidia_client
from backend.llm.prompt_builder import PromptBuilder
from backend.rag.singleton import get_retriever
from backend.auth import TokenData, require_role
from backend.utils.audit import write_audit_log
from backend.config import get_settings

settings = get_settings()

router = APIRouter(prefix="/api", tags=["Chat"])

prompt_builder = PromptBuilder()
retriever = get_retriever()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_utc(dt: Optional[datetime]) -> Optional[str]:
    if not dt:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def is_general_cyber_question(message: str) -> bool:
    msg = (message or "").lower().strip()

    patterns = [
        r"\bwhat is\b",
        r"\bwhat are\b",
        r"\bdefine\b",
        r"\bmeaning of\b",
        r"\bexplain\b",
        r"\bdifference between\b",
        r"\bcompare\b",
        r"\bhow does\b",
        r"\bhow do\b",
        r"\bwhy is\b",
    ]

    keywords = [
        "cybersecurity",
        "network security",
        "endpoint security",
        "phishing",
        "spear phishing",
        "smishing",
        "vishing",
        "firewall",
        "vpn",
        "proxy",
        "ids",
        "ips",
        "waf",
        "siem",
        "soar",
        "xdr",
        "edr",
        "ndr",
        "mfa",
        "iam",
        "sso",
        "zero trust",
        "malware",
        "ransomware",
        "trojan",
        "worm",
        "virus",
        "rootkit",
        "botnet",
        "social engineering",
        "spoofing",
        "encryption",
        "hashing",
        "cve",
        "vulnerability",
        "threat intelligence",
        "mitre",
        "attack",
    ]

    if any(re.search(p, msg) for p in patterns):
        return True

    return any(k in msg for k in keywords)


def should_use_rag_for_chat(message: str) -> bool:
    """
    Fast RAG policy.

    Do not retrieve KB context for simple educational questions.
    Use RAG only when the user seems to ask about:
    - internal docs
    - uploaded KB
    - playbooks/runbooks
    - policies
    - incident procedures
    - MITRE/CVE details where KB may help
    """

    msg = (message or "").lower().strip()

    if not msg:
        return False

    rag_keywords = [
        "knowledge base",
        "uploaded document",
        "uploaded docs",
        "according to uploaded",
        "according to our",
        "internal",
        "policy",
        "procedure",
        "runbook",
        "playbook",
        "past incident",
        "previous incident",
        "our environment",
        "company",
        "organization",
        "document",
        "kb",
        "mitre",
        "attack technique",
        "cve-",
        "ransomware playbook",
        "incident response",
        "containment procedure",
    ]

    if any(k in msg for k in rag_keywords):
        return True

    if is_general_cyber_question(message):
        return False

    return False


def _scope_chat_query(query, current_user: TokenData):
    if current_user.role == "admin":
        return query

    return query.filter(ChatSession.user_id == current_user.user_id)


def _sanitize_chat_response(text: str) -> str:
    if not text or not isinstance(text, str):
        return ""

    cleaned = str(text)
    cleaned = re.sub(r"[\u200b\ufeff\u2060]", "", cleaned).strip()

    # Unwrap if entire response is wrapped in a code fence.
    if cleaned.startswith("```") and "```" in cleaned[3:]:
        parts = cleaned.split("```")
        if len(parts) >= 3:
            cleaned = "```".join(parts[1:-1]).strip()

    # Drop a language line like "markdown", "md", or "text".
    if "\n" in cleaned:
        first = cleaned.split("\n", 1)[0].strip().lower()
        if first in {"markdown", "md", "text"}:
            cleaned = cleaned.split("\n", 1)[1].strip()

    cleaned = cleaned.lstrip()

    # Aggressively strip ALL leading "Summary" variants.
    # Loop until no more summary prefixes remain.
    for _ in range(3):
        prev = cleaned
        patterns = [
            # ## Summary: or # Summary or ### **Summary**:
            r"^(#{1,6}\s*)?\*{0,2}\s*summary\s*\*{0,2}\s*:?\s*\n+",
            r"^(#{1,6}\s*)?\*{0,2}\s*summary\s*\*{0,2}\s*:?\s*",
            # "Here's a summary:"
            r"^here(?:'|')s\s+a\s+summary\s*:?\s*",
            # "Here is the summary:"
            r"^here\s+is\s+(?:the\s+)?summary\s*:?\s*",
            # Just the word "Summary" alone on a line
            r"^summary\s*\n+",
            # "Summary:" at the very start
            r"^summary\s*:\s*",
            # Bold summary: **Summary** or **Summary:**
            r"^\*{2}summary\*{2}\s*:?\s*\n*",
        ]

        for pat in patterns:
            if re.match(pat, cleaned, flags=re.IGNORECASE):
                cleaned = re.sub(
                    pat,
                    "",
                    cleaned,
                    count=1,
                    flags=re.IGNORECASE,
                ).lstrip()
                break

        if cleaned == prev:
            break

    return cleaned.strip()


def _derive_chat_title_from_text(text: str, max_len: int = 72) -> str:
    if not text or not isinstance(text, str):
        return "New SOC Chat"

    t = text.strip()
    t = re.sub(r"```.*?```", " ", t, flags=re.DOTALL)
    t = re.sub(r"\s+", " ", t).strip()
    t = re.sub(r"^\s*#{1,6}\s*", "", t).strip()

    if len(t) < 3:
        return "New SOC Chat"

    if len(t) > max_len:
        t = t[:max_len].rstrip() + "…"

    return t


def _get_first_user_message_for_session(
    db: Session,
    session_id: str,
    current_user: TokenData,
) -> Optional[str]:
    q = (
        db.query(ChatSession.content)
        .filter(ChatSession.session_id == session_id)
        .filter(func.lower(ChatSession.role) == "user")
        .order_by(ChatSession.created_at.asc())
    )

    q = _scope_chat_query(q, current_user)

    row = q.first()

    return row[0] if row else None


def _get_titles_for_sessions(
    db: Session,
    session_ids: List[str],
    current_user: TokenData,
) -> Dict[str, str]:
    if not session_ids:
        return {}

    q = (
        db.query(
            ChatSession.session_id,
            ChatSession.content,
            ChatSession.created_at,
        )
        .filter(ChatSession.session_id.in_(session_ids))
        .filter(func.lower(ChatSession.role) == "user")
        .order_by(ChatSession.session_id.asc(), ChatSession.created_at.asc())
    )

    q = _scope_chat_query(q, current_user)

    rows = q.all()

    first_by_sid: Dict[str, str] = {}

    for sid, content, _ts in rows:
        if sid not in first_by_sid and content:
            first_by_sid[sid] = content

    return {
        sid: _derive_chat_title_from_text(txt)
        for sid, txt in first_by_sid.items()
    }


def _load_recent_history(
    db: Session,
    session_id: str,
    current_user: TokenData,
    limit: int = 10,
) -> List[Dict[str, str]]:
    """
    Load latest N messages, preserving chronological order.

    Previous code ordered ascending + limit(20), which selected oldest messages.
    This version selects latest messages first, then reverses.
    """

    q = (
        db.query(ChatSession)
        .filter(ChatSession.session_id == session_id)
        .order_by(ChatSession.created_at.desc())
    )

    q = _scope_chat_query(q, current_user)

    latest = q.limit(limit).all()
    records = list(reversed(latest))

    return [
        {
            "role": r.role,
            "content": r.content,
        }
        for r in records
        if r.role in {"user", "assistant"} and r.content
    ]


class ChatRequest(BaseModel):
    session_id: Optional[str] = Field(
        None,
        description="Conversation session ID",
    )
    message: str = Field(..., min_length=1, max_length=5000)
    use_rag: bool = Field(
        True,
        description="Enable RAG context retrieval",
    )


class ChatResponse(BaseModel):
    session_id: str
    response: str
    rag_used: bool
    history_length: int
    title: Optional[str] = None


@router.post("/chat", response_model=ChatResponse)
def chat(
    req: ChatRequest,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Backward-compatible blocking chat endpoint.

    The frontend should prefer /api/chat/stream for better UX.
    """

    t0 = time.perf_counter()

    session_id = (req.session_id or str(uuid.uuid4())).strip()

    existing = db.query(ChatSession).filter(ChatSession.session_id == session_id).first()

    if existing and existing.user_id and existing.user_id != current_user.user_id:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to use this session_id.",
        )

    history = _load_recent_history(
        db=db,
        session_id=session_id,
        current_user=current_user,
        limit=10,
    )

    t_db = time.perf_counter()

    rag_context = None
    general_question = is_general_cyber_question(req.message)
    use_rag_now = bool(req.use_rag and should_use_rag_for_chat(req.message))

    if use_rag_now:
        try:
            top_k = 2 if general_question else 3
            results = retriever.retrieve(req.message, top_k=top_k)

            if results:
                rag_context = retriever.format_context(results)

        except Exception as e:
            logger.warning(f"[Chat] RAG retrieval failed: {e}")

    t_rag = time.perf_counter()

    messages = prompt_builder.build_chat_prompt(
        history=history,
        user_message=req.message,
        context=rag_context,
    )

    user_ts = _utc_now()

    try:
        max_tokens = 350 if general_question else 600

        response_text = nvidia_client.chat(
            messages,
            temperature=0.25,
            max_tokens=max_tokens,
            timeout_seconds=120,
            model=getattr(settings, "nvidia_chat_model", None) or settings.nvidia_model,
        )

        response_text = _sanitize_chat_response(response_text)

    except TimeoutError:
        raise HTTPException(
            status_code=503,
            detail="AI model timed out. Try a shorter question.",
        )

    except PermissionError:
        raise HTTPException(
            status_code=401,
            detail="NVIDIA API authentication failed.",
        )

    except RuntimeError as e:
        error_str = str(e).lower()

        if "rate limit" in error_str or "429" in error_str:
            raise HTTPException(
                status_code=429,
                detail="Rate limit reached. Wait and retry.",
            )

        if "503" in error_str or "unavailable" in error_str:
            raise HTTPException(
                status_code=503,
                detail="AI service temporarily unavailable.",
            )

        raise HTTPException(
            status_code=503,
            detail=f"AI service error: {str(e)}",
        )

    except Exception as e:
        logger.error(f"[Chat] Unexpected LLM error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Unexpected error. Please try again.",
        )

    t_llm = time.perf_counter()
    assistant_ts = _utc_now()

    try:
        user_msg = ChatSession(
            session_id=session_id,
            user_id=current_user.user_id,
            role="user",
            content=req.message,
            created_at=user_ts,
        )

        ai_msg = ChatSession(
            session_id=session_id,
            user_id=current_user.user_id,
            role="assistant",
            content=response_text,
            created_at=assistant_ts,
        )

        db.add_all([user_msg, ai_msg])
        db.commit()

    except Exception as e:
        logger.error(f"[Chat] Failed to persist conversation: {e}")

    first_user_msg = _get_first_user_message_for_session(
        db,
        session_id,
        current_user,
    )

    title = _derive_chat_title_from_text(first_user_msg or req.message)

    write_audit_log(
        db,
        "chat_message_processed",
        {
            "session_id": session_id,
            "username": current_user.username,
            "role": current_user.role,
            "rag_used": rag_context is not None,
            "general_question": general_question,
            "history_length": len(history),
            "message_preview": req.message[:200],
            "timing_seconds": {
                "db_history": round(t_db - t0, 3),
                "rag": round(t_rag - t_db, 3),
                "llm": round(t_llm - t_rag, 3),
                "total": round(t_llm - t0, 3),
            },
        },
        user_id=current_user.user_id,
    )

    logger.info(
        f"[chat] session={session_id[:8]} user={current_user.username} "
        f"db={t_db - t0:.2f}s rag={t_rag - t_db:.2f}s "
        f"llm={t_llm - t_rag:.2f}s total={t_llm - t0:.2f}s "
        f"rag_used={rag_context is not None}"
    )

    return ChatResponse(
        session_id=session_id,
        response=response_text,
        rag_used=rag_context is not None,
        history_length=len(history) + 2,
        title=title,
    )


@router.post("/chat/stream")
def chat_stream(
    req: ChatRequest,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    """
    Streaming SOC chat endpoint.

    Returns text/event-stream events:
    - meta
    - token
    - done
    - error
    """

    t0 = time.perf_counter()

    session_id = (req.session_id or str(uuid.uuid4())).strip()

    existing = db.query(ChatSession).filter(ChatSession.session_id == session_id).first()

    if existing and existing.user_id and existing.user_id != current_user.user_id:
        raise HTTPException(
            status_code=403,
            detail="You are not allowed to use this session_id.",
        )

    history = _load_recent_history(
        db=db,
        session_id=session_id,
        current_user=current_user,
        limit=10,
    )

    t_db = time.perf_counter()

    rag_context = None
    general_question = is_general_cyber_question(req.message)
    use_rag_now = bool(req.use_rag and should_use_rag_for_chat(req.message))

    if use_rag_now:
        try:
            top_k = 2 if general_question else 3
            results = retriever.retrieve(req.message, top_k=top_k)

            if results:
                rag_context = retriever.format_context(results)

        except Exception as e:
            logger.warning(f"[ChatStream] RAG retrieval failed: {e}")

    t_rag = time.perf_counter()

    messages = prompt_builder.build_chat_prompt(
        history=history,
        user_message=req.message,
        context=rag_context,
    )

    user_ts = _utc_now()
    rag_used = rag_context is not None
    chat_model = getattr(settings, "nvidia_chat_model", None) or settings.nvidia_model
    max_tokens = 350 if general_question else 600

    def sse_event(event: str, payload: dict) -> str:
        return (
            f"event: {event}\n"
            f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
        )

    def generate():
        full_response_parts: List[str] = []
        title = _derive_chat_title_from_text(req.message)

        try:
            yield sse_event(
                "meta",
                {
                    "session_id": session_id,
                    "rag_used": rag_used,
                    "status": "started",
                    "model": chat_model,
                },
            )

            for chunk in nvidia_client.stream_chat(
                messages,
                temperature=0.25,
                max_tokens=max_tokens,
                timeout_seconds=120,
                model=chat_model,
            ):
                if not chunk:
                    continue

                full_response_parts.append(chunk)

                yield sse_event(
                    "token",
                    {
                        "delta": chunk,
                    },
                )

            assistant_ts = _utc_now()
            response_text = _sanitize_chat_response("".join(full_response_parts))

            persist_db = SessionLocal()

            try:
                user_msg = ChatSession(
                    session_id=session_id,
                    user_id=current_user.user_id,
                    role="user",
                    content=req.message,
                    created_at=user_ts,
                )

                ai_msg = ChatSession(
                    session_id=session_id,
                    user_id=current_user.user_id,
                    role="assistant",
                    content=response_text,
                    created_at=assistant_ts,
                )

                persist_db.add_all([user_msg, ai_msg])
                persist_db.commit()

                first_user_msg = _get_first_user_message_for_session(
                    persist_db,
                    session_id,
                    current_user,
                )

                title = _derive_chat_title_from_text(first_user_msg or req.message)

                t_done = time.perf_counter()

                write_audit_log(
                    persist_db,
                    "chat_message_streamed",
                    {
                        "session_id": session_id,
                        "username": current_user.username,
                        "role": current_user.role,
                        "rag_used": rag_used,
                        "general_question": general_question,
                        "history_length": len(history),
                        "message_preview": req.message[:200],
                        "model": chat_model,
                        "timing_seconds": {
                            "db_history": round(t_db - t0, 3),
                            "rag": round(t_rag - t_db, 3),
                            "total_until_stream_done": round(t_done - t0, 3),
                        },
                    },
                    user_id=current_user.user_id,
                )

            except Exception as e:
                logger.error(f"[ChatStream] Failed to persist conversation: {e}")

            finally:
                persist_db.close()

            yield sse_event(
                "done",
                {
                    "session_id": session_id,
                    "rag_used": rag_used,
                    "title": title,
                    "history_length": len(history) + 2,
                },
            )

        except PermissionError:
            yield sse_event(
                "error",
                {
                    "message": "NVIDIA API authentication failed.",
                },
            )

        except TimeoutError:
            yield sse_event(
                "error",
                {
                    "message": "AI model timed out. Try a shorter question.",
                },
            )

        except RuntimeError as e:
            err = str(e)

            if "rate limit" in err.lower() or "429" in err.lower():
                yield sse_event(
                    "error",
                    {
                        "message": "NVIDIA rate limit reached. Wait and retry.",
                    },
                )
            else:
                logger.error(f"[ChatStream] NVIDIA runtime error: {e}")
                yield sse_event(
                    "error",
                    {
                        "message": f"AI service error: {err}",
                    },
                )

        except Exception as e:
            logger.exception(f"[ChatStream] Unexpected stream error: {e}")
            yield sse_event(
                "error",
                {
                    "message": "Unexpected chat streaming error. Please try again.",
                },
            )

    headers = {
        "Cache-Control": "no-cache",
        "Connection": "keep-alive",
        "X-Accel-Buffering": "no",
    }

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers=headers,
    )


@router.get("/chat/history/{session_id}")
def get_chat_history(
    session_id: str,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    query = (
        db.query(ChatSession)
        .filter(ChatSession.session_id == session_id)
        .order_by(ChatSession.created_at.asc())
    )

    query = _scope_chat_query(query, current_user)

    records = query.all()

    if not records:
        return {
            "session_id": session_id,
            "title": "New SOC Chat",
            "owner": None,
            "message_count": 0,
            "messages": [],
        }

    owner = None

    if current_user.role == "admin":
        owner_user_id = next((r.user_id for r in records if r.user_id), None)

        if owner_user_id:
            u = db.query(User).filter(User.id == owner_user_id).first()

            if u:
                owner = {
                    "user_id": u.id,
                    "display_id": getattr(u, "display_id", None),
                    "username": getattr(u, "original_username", None) or u.username,
                }

    first_user_msg = next(
        (
            r.content
            for r in records
            if (r.role or "").lower() == "user" and r.content
        ),
        None,
    )

    title = _derive_chat_title_from_text(first_user_msg)

    return {
        "session_id": session_id,
        "title": title,
        "owner": owner,
        "message_count": len(records),
        "messages": [
            {
                "role": r.role,
                "content": r.content,
                "timestamp": _iso_utc(r.created_at),
            }
            for r in records
        ],
    }


@router.delete("/chat/history/{session_id}")
def clear_chat_history(
    session_id: str,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    query = db.query(ChatSession).filter(ChatSession.session_id == session_id)
    query = _scope_chat_query(query, current_user)

    deleted = query.delete()
    db.commit()

    write_audit_log(
        db,
        "chat_history_cleared",
        {
            "session_id": session_id,
            "cleared_by": current_user.username,
            "role": current_user.role,
            "messages_deleted": deleted,
        },
        user_id=current_user.user_id,
    )

    return {
        "success": True,
        "session_id": session_id,
        "messages_deleted": deleted,
    }


@router.get("/chat/sessions")
def list_sessions(
    limit: int = 20,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    if current_user.role == "admin":
        username_expr = func.coalesce(User.original_username, User.username).label(
            "username"
        )

        query = (
            db.query(
                ChatSession.session_id.label("session_id"),
                ChatSession.user_id.label("user_id"),
                User.display_id.label("display_id"),
                username_expr,
                func.count(ChatSession.id).label("message_count"),
                func.max(ChatSession.created_at).label("last_active"),
            )
            .join(User, User.id == ChatSession.user_id, isouter=True)
            .group_by(
                ChatSession.session_id,
                ChatSession.user_id,
                User.display_id,
                User.username,
                User.original_username,
            )
            .order_by(func.max(ChatSession.created_at).desc())
            .limit(limit)
        )

    else:
        query = (
            db.query(
                ChatSession.session_id.label("session_id"),
                func.count(ChatSession.id).label("message_count"),
                func.max(ChatSession.created_at).label("last_active"),
            )
            .filter(ChatSession.user_id == current_user.user_id)
            .group_by(ChatSession.session_id)
            .order_by(func.max(ChatSession.created_at).desc())
            .limit(limit)
        )

    sessions = query.all()
    session_ids = [s.session_id for s in sessions]
    titles_by_sid = _get_titles_for_sessions(db, session_ids, current_user)

    write_audit_log(
        db,
        "chat_sessions_listed",
        {
            "listed_by": current_user.username,
            "role": current_user.role,
            "limit": limit,
        },
        user_id=current_user.user_id,
    )

    if current_user.role == "admin":
        return {
            "total": len(sessions),
            "sessions": [
                {
                    "session_id": s.session_id,
                    "title": titles_by_sid.get(s.session_id, "New SOC Chat"),
                    "user_id": s.user_id,
                    "display_id": s.display_id,
                    "username": s.username,
                    "message_count": s.message_count,
                    "last_active": _iso_utc(s.last_active),
                }
                for s in sessions
            ],
        }

    return {
        "total": len(sessions),
        "sessions": [
            {
                "session_id": s.session_id,
                "title": titles_by_sid.get(s.session_id, "New SOC Chat"),
                "message_count": s.message_count,
                "last_active": _iso_utc(s.last_active),
            }
            for s in sessions
        ],
    }
