# backend/database.py
"""
Database Models — SQLAlchemy

Supports:
- PostgreSQL (recommended for production)
- SQLite (dev/testing)

Notes:
- Uses timezone-aware UTC timestamps (DateTime(timezone=True) + utcnow()).
- For production, prefer Alembic migrations; create_all is for convenience/dev.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import (
    create_engine,
    Column,
    String,
    Integer,
    Float,
    DateTime,
    Text,
    Boolean,
    inspect,
    text,
    event,
)
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from backend.config import get_settings

settings = get_settings()
DATABASE_URL = settings.database_url.strip()
IS_SQLITE = DATABASE_URL.lower().startswith("sqlite")


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ---- JSON type: JSONB for Postgres, JSON for SQLite/others ----
try:
    if "postgresql" in DATABASE_URL.lower():
        from sqlalchemy.dialects.postgresql import JSONB as _JSON_TYPE  # type: ignore
    else:
        from sqlalchemy import JSON as _JSON_TYPE  # type: ignore
except Exception:
    from sqlalchemy import JSON as _JSON_TYPE  # type: ignore


# ---- Engine creation ----
engine_kwargs = {
    "pool_pre_ping": True,
    "future": True,
}
if IS_SQLITE:
    engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, future=True)
Base = declarative_base()

DISPLAY_ID_PREFIX = "usr_"
DISPLAY_ID_HEX_LEN = 16


# -------------------------------------------------------------------
# Models
# -------------------------------------------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    display_id = Column(String, unique=True, nullable=True, index=True)

    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)

    role = Column(String, nullable=False, default="analyst")
    is_active = Column(Boolean, nullable=False, default=True)

    # Soft-delete / retention
    original_username = Column(String, nullable=True, index=True)
    original_email = Column(String, nullable=True, index=True)
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)
    deleted_by_user_id = Column(String, nullable=True)
    purged_at = Column(DateTime(timezone=True), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "display_id": self.display_id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


@event.listens_for(User, "before_insert")
def _user_before_insert(mapper, connection, target: User):
    if not getattr(target, "id", None):
        target.id = str(uuid.uuid4())
    if not getattr(target, "display_id", None):
        compact = (target.id or "").replace("-", "")
        target.display_id = DISPLAY_ID_PREFIX + compact[:DISPLAY_ID_HEX_LEN]


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_source = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    affected_asset = Column(String)
    ioc_list = Column(Text)
    mitre_mapping = Column(String)
    raw_alert = Column(Text)
    created_by = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class AlertResponse(Base):
    __tablename__ = "alert_responses"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String, nullable=False, index=True)

    triage_decision = Column(String)
    risk_level = Column(String)
    attack_type = Column(String)
    explanation = Column(Text)

    recommended_actions = Column(_JSON_TYPE)
    confidence_score = Column(Float)
    source_citations = Column(_JSON_TYPE)
    follow_up_questions = Column(_JSON_TYPE)
    enrichment_data = Column(_JSON_TYPE)

    playbook = Column(Text)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class Feedback(Base):
    """
    Analyst/Admin feedback used for quality + bounded calibration.
    verdict:
    - tp (true positive)
    - fp (false positive)
    - benign
    - unknown
    """
    __tablename__ = "feedback"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String, nullable=False, index=True)

    incident_type = Column(String, nullable=True, index=True)
    verdict = Column(String, nullable=False, index=True)
    notes = Column(Text, nullable=True)

    created_by_user_id = Column(String, nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class ConfidenceCalibration(Base):
    """
    Bounded tuning results per incident_type.
    Stores multiplier applied to confidence_final (0..1) after base formula.
    """
    __tablename__ = "confidence_calibrations"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    incident_type = Column(String, nullable=False, unique=True, index=True)

    final_multiplier = Column(Float, nullable=False, default=1.0)
    sample_count = Column(Integer, nullable=False, default=0)
    tp_count = Column(Integer, nullable=False, default=0)
    fp_count = Column(Integer, nullable=False, default=0)

    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class ChatSession(Base):
    __tablename__ = "chat_sessions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    session_id = Column(String, nullable=False, index=True)
    user_id = Column(String, nullable=True, index=True)

    role = Column(String, nullable=False, index=True)
    content = Column(Text, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)


class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    event_type = Column(String)
    event_data = Column(_JSON_TYPE)
    user_id = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)


class KnowledgeBaseDocument(Base):
    __tablename__ = "knowledge_base_documents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String, nullable=False, index=True)
    doc_type = Column(String, nullable=False, index=True)
    source = Column(String, nullable=False, index=True)

    uploaded_by_user_id = Column(String, nullable=True)
    uploaded_by_username = Column(String, nullable=True)

    file_size_bytes = Column(Integer, default=0)
    chunks_ingested = Column(Integer, default=0)
    preview_text = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "doc_type": self.doc_type,
            "source": self.source,
            "uploaded_by_user_id": self.uploaded_by_user_id,
            "uploaded_by_username": self.uploaded_by_username,
            "file_size_bytes": self.file_size_bytes,
            "chunks_ingested": self.chunks_ingested,
            "preview_text": self.preview_text,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class EvidenceArtifact(Base):
    """
    Evidence artifacts produced by query execution (Splunk/Sentinel/manual upload).
    Stored fully in DB but capped in your ingestion logic.
    """
    __tablename__ = "evidence_artifacts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    alert_id = Column(String, nullable=False, index=True)

    connector = Column(String, nullable=False)  # splunk | sentinel | manual
    query_name = Column(String, nullable=False)
    query_text = Column(Text, nullable=False)

    status = Column(String, nullable=False, default="ingested")  # ingested|failed|truncated
    executed_by = Column(String, nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)

    row_count = Column(Integer, nullable=False, default=0)
    rows_json = Column(_JSON_TYPE, nullable=False, default=list)
    warnings = Column(_JSON_TYPE, nullable=False, default=list)
    rows_hash = Column(String, nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow)


# -------------------------------------------------------------------
# Lightweight schema patching for existing SQLite DBs
# (kept from your original; for production use Alembic)
# -------------------------------------------------------------------
def _ensure_user_columns():
    insp = inspect(engine)
    try:
        cols = {c["name"] for c in insp.get_columns("users")}
    except Exception:
        return

    alters = []
    for name, ddl in [
        ("display_id", "ALTER TABLE users ADD COLUMN display_id VARCHAR"),
        ("original_username", "ALTER TABLE users ADD COLUMN original_username VARCHAR"),
        ("original_email", "ALTER TABLE users ADD COLUMN original_email VARCHAR"),
        ("deleted_at", "ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP"),
        ("deleted_by_user_id", "ALTER TABLE users ADD COLUMN deleted_by_user_id VARCHAR"),
        ("purged_at", "ALTER TABLE users ADD COLUMN purged_at TIMESTAMP"),
    ]:
        if name not in cols:
            alters.append(ddl)

    if alters:
        with engine.begin() as conn:
            for stmt in alters:
                try:
                    conn.execute(text(stmt))
                except Exception:
                    # ignore in Postgres or if already exists
                    pass


def _backfill_display_ids():
    try:
        with engine.begin() as conn:
            rows = conn.execute(
                text("SELECT id FROM users WHERE display_id IS NULL OR display_id = ''")
            ).fetchall()
            for (uid,) in rows:
                compact = (uid or "").replace("-", "")
                did = DISPLAY_ID_PREFIX + compact[:DISPLAY_ID_HEX_LEN]
                conn.execute(
                    text("UPDATE users SET display_id = :did WHERE id = :uid"),
                    {"did": did, "uid": uid},
                )
    except Exception:
        # safe no-op for fresh DBs
        return


def init_db():
    """
    For production, prefer Alembic migrations.
    For now, create_all keeps your app running.
    """
    Base.metadata.create_all(bind=engine)
    _ensure_user_columns()
    _backfill_display_ids()


def get_db() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI routes.

    NOTE: SessionLocal is a sessionmaker factory; the yielded object is a Session.
    """
    db: Session = SessionLocal()
    try:
        yield db
    finally:
        db.close()