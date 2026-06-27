from __future__ import annotations

from sqlalchemy import Column, String, DateTime, Integer, Text, ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql import func

from backend.database import Base


class EvidenceArtifact(Base):
    __tablename__ = "evidence_artifacts"

    id = Column(String, primary_key=True)  # uuid str
    alert_id = Column(String, ForeignKey("alerts.id"), index=True, nullable=False)

    connector = Column(String, nullable=False)  # splunk | sentinel | manual
    query_name = Column(String, nullable=False)
    query_text = Column(Text, nullable=False)

    status = Column(String, nullable=False, default="ingested")  # ingested|failed|truncated
    executed_by = Column(String, nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)

    row_count = Column(Integer, nullable=False, default=0)
    rows_json = Column(JSONB, nullable=False, default=list)      # capped rows
    warnings = Column(JSONB, nullable=False, default=list)       # truncation, parse warnings
    rows_hash = Column(String, nullable=True)                    # sha256 of canonicalized rows

    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)