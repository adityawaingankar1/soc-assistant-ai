# backend/main.py
from __future__ import annotations

import os
import backend  # noqa: F401
import backend.firebase_admin
import uvicorn


from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from fastapi.responses import JSONResponse

from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from loguru import logger

from backend.api.routes_auth import router as auth_router
from backend.api.routes_alert import router as alert_router
from backend.api.routes_chat import router as chat_router
from backend.api.routes_docs import router as docs_router
from backend.api.routes_export import router as export_router
from backend.api.routes_stream import router as stream_router
from backend.api.routes_admin import router as admin_router
from backend.api.routes_dashboard import router as dashboard_router
from backend.api.routes_playbooks import router as playbooks_router
from backend.api.routes_feedback import router as feedback_router
from backend.api.routes_tasks import router as tasks_router  # <-- keep with other routers

# NEW (optional): investigation routes (Splunk/Sentinel execution + evidence store)
try:
    from backend.api.routes_investigation import router as investigation_router  # type: ignore
except Exception:
    investigation_router = None  # type: ignore

from backend.database import init_db
from backend.config import get_settings
from backend.middleware.rate_limit import limiter
from backend.middleware.request_context import RequestContextMiddleware
from backend.utils.api_response import error_response
from prometheus_fastapi_instrumentator import Instrumentator

settings = get_settings()


def _check_redis() -> dict:
    """
    Best-effort Redis ping for health endpoint.
    """
    try:
        import redis  # type: ignore

        # Prefer explicit env if present; fallback to docker-compose service name
        redis_url = os.getenv("REDIS_URL", "").strip() or "redis://redis:6379/0"
        r = redis.Redis.from_url(redis_url, socket_connect_timeout=1, socket_timeout=1)
        ok = bool(r.ping())
        return {"ok": ok, "url": redis_url, "error": None if ok else "ping_failed"}
    except Exception as e:
        return {"ok": False, "url": os.getenv("REDIS_URL", "").strip() or "redis://redis:6379/0", "error": str(e)}


def _check_neo4j() -> dict:
    """
    Best-effort Neo4j ping for health endpoint.
    Respects Neo4jClient.disabled behavior (missing credentials -> disabled).
    """
    try:
        from backend.graph.neo4j_client import Neo4jClient  # type: ignore

        client = Neo4jClient()
        if getattr(client, "disabled", False):
            return {"ok": False, "disabled": True, "error": "disabled_missing_credentials"}

        res = client.run("RETURN 1 AS ok")
        try:
            client.close()
        except Exception:
            pass

        ok = res is not None
        return {"ok": bool(ok), "disabled": False, "error": None if ok else "no_result"}
    except Exception as e:
        return {"ok": False, "disabled": False, "error": str(e)}


def _check_celery_broker() -> dict:
    """
    Broker connectivity check (not worker ping).
    """
    try:
        from backend.celery_app import celery_app  # type: ignore

        # Connection ensure -> validates broker is reachable.
        with celery_app.connection_for_write() as conn:
            conn.ensure_connection(max_retries=1)

        return {"ok": True, "error": None}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("SOC Assistant starting up...")

    # realtime bus setup
    try:
        import asyncio
        from backend.realtime.event_bus import set_main_loop, start_publisher

        loop = asyncio.get_running_loop()
        set_main_loop(loop)
        start_publisher(loop)
    except Exception as e:
        logger.warning(f"Realtime bus init failed (non-fatal): {e}")

    app.state.startup_ok = False
    app.state.rag_ready = False
    app.state.db_ready = False

    # DB init
    try:
        init_db()
        app.state.db_ready = True
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")

    # RAG preload
    try:
        from backend.rag.singleton import get_ingestion

        ingestion = get_ingestion()
        # ingestion.load_sample_knowledge_base()
        app.state.rag_ready = True
        logger.info("RAG knowledge base loaded")
    except Exception as e:
        logger.warning(f"RAG preload failed: {e}")

    app.state.startup_ok = bool(app.state.db_ready)
    logger.info("SOC Assistant ready")

    yield

    logger.info("Shutting down...")


app = FastAPI(
    title="SOC Assistant API",
    description="AI-Powered Security Incident Triage & Response Playbook Generator",
    version="1.0.0",
    lifespan=lifespan,
)
Instrumentator().instrument(app).expose(app)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(RequestContextMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.frontend_url, "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", None)
    logger.exception(f"[Unhandled] request_id={request_id} error={exc}")
    return JSONResponse(
        status_code=500,
        content=error_response(
            message="Internal server error",
            code="INTERNAL_SERVER_ERROR",
            request_id=request_id,
        ),
    )


# Routers
app.include_router(alert_router)
app.include_router(chat_router)
app.include_router(docs_router)
app.include_router(auth_router)
app.include_router(export_router)
app.include_router(stream_router)
app.include_router(admin_router)
app.include_router(dashboard_router)
app.include_router(playbooks_router)
app.include_router(feedback_router)
app.include_router(tasks_router)  # <-- moved up (was at bottom)

if investigation_router is not None:
    app.include_router(investigation_router)
    logger.info("Investigation routes enabled")
else:
    logger.warning("Investigation routes not loaded (backend.api.routes_investigation not found)")


@app.get("/")
def root():
    return {
        "service": "SOC Assistant API",
        "version": "1.0.0",
        "status": "operational",
        "environment": settings.environment,
    }


@app.get("/health")
def health():
    """
    Extended health endpoint:
    ✅ Redis ping
    ✅ Neo4j ping
    ✅ Celery broker ping
    """
    redis_health = _check_redis()
    neo4j_health = _check_neo4j()
    celery_broker_health = _check_celery_broker()

    # Keep overall status aligned with core readiness, but surface dependency health.
    core_ok = bool(getattr(app.state, "startup_ok", False))
    deps_ok = bool(redis_health.get("ok")) and bool(celery_broker_health.get("ok")) and (
        bool(neo4j_health.get("ok")) or bool(neo4j_health.get("disabled"))
    )

    status = "healthy" if (core_ok and deps_ok) else "degraded"

    return {
        "status": status,
        "model": settings.nvidia_model,
        "debug": settings.debug,
        "environment": settings.environment,
        "db_ready": getattr(app.state, "db_ready", False),
        "rag_ready": getattr(app.state, "rag_ready", False),
        "dependencies": {
            "redis": redis_health,
            "neo4j": neo4j_health,
            "celery_broker": celery_broker_health,
        },
    }


@app.get("/ready")
def ready():
    ready_state = bool(getattr(app.state, "db_ready", False))
    return {
        "ready": ready_state,
        "db_ready": getattr(app.state, "db_ready", False),
        "rag_ready": getattr(app.state, "rag_ready", False),
    }


@app.get("/system/status")
def system_status():
    return {
        "app": {"name": "SOC Assistant API", "version": "1.0.0", "environment": settings.environment},
        "services": {
            "database": "up" if getattr(app.state, "db_ready", False) else "down",
            "rag": "up" if getattr(app.state, "rag_ready", False) else "degraded",
        },
        "model": {"provider": "NVIDIA", "name": settings.nvidia_model},
    }


if __name__ == "__main__":
    uvicorn.run(
        "backend.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.debug,
    )