"""
Export Routes — with RBAC
CSV export  → all authenticated roles
PDF export  → admin + analyst only
"""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.database import get_db, Alert, AlertResponse
from backend.auth import TokenData, require_role
from backend.utils.audit import write_audit_log
from loguru import logger

router = APIRouter(prefix="/api/export", tags=["Export"])

BASE_DIR = Path(__file__).resolve().parents[1]
FONT_DIR = BASE_DIR / "fonts"
REG_FONT = FONT_DIR / "DejaVuSans.ttf"
BOLD_FONT = FONT_DIR / "DejaVuSans-Bold.ttf"

# Characters that commonly cause export/render issues or appear as "￾"
_BAD_EXPORT_CHARS_RX = re.compile(r"[\u200b\ufeff\ufffe\uffff\u00ad\u2060]")


def pdf_safe_unicode(text) -> str:
    if text is None:
        return "-"
    text = str(text)
    text = _BAD_EXPORT_CHARS_RX.sub("", text)
    replacements = {
        "→": "->",
        "\u00a0": " ",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text


def pdf_safe_latin1(text) -> str:
    if text is None:
        return "-"
    text = str(text)
    text = _BAD_EXPORT_CHARS_RX.sub("", text)
    replacements = {
        "—": "-",
        "–": "-",
        "‘": "'",
        "’": "'",
        "“": '"',
        "”": '"',
        "•": "-",
        "→": "->",
        "…": "...",
        "✅": "[OK]",
        "❌": "[X]",
        "⚠️": "[!]",
        "🔒": "[LOCK]",
        "📄": "[DOC]",
        "📚": "[KB]",
        "🔍": "[SEARCH]",
        "🛡️": "[SECURITY]",
        "🎉": "[DONE]",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)
    return text.encode("latin-1", "ignore").decode("latin-1")


def try_register_unicode_fonts(pdf) -> bool:
    """
    Registers Unicode fonts for fpdf2. If unavailable, the code falls back to latin-1 safe text.
    """
    try:
        if not REG_FONT.exists() or not BOLD_FONT.exists():
            logger.warning("[Export] Unicode fonts not found, using latin-1 fallback")
            return False

        # uni=True is important for fpdf2 TTF unicode support
        pdf.add_font("DejaVu", "", str(REG_FONT), uni=True)
        pdf.add_font("DejaVu", "B", str(BOLD_FONT), uni=True)
        logger.info("[Export] Unicode fonts loaded successfully")
        return True
    except Exception as e:
        logger.warning(f"[Export] Failed to load Unicode fonts, using latin-1 fallback: {e}")
        return False


def _csv_safe_cell(v) -> str:
    """
    Mitigates CSV/Excel formula injection by prefixing dangerous leading characters.
    """
    s = "" if v is None else str(v)
    if s[:1] in ("=", "+", "-", "@"):
        return "'" + s
    return s


@router.get("/alerts/csv")
def export_alerts_csv(
    limit: int = 100,
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db),
):
    alerts = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .limit(limit)
        .all()
    )

    # Prefetch responses to avoid N+1 queries
    alert_ids = [a.id for a in alerts]
    responses = {}
    if alert_ids:
        resp_rows = db.query(AlertResponse).filter(AlertResponse.alert_id.in_(alert_ids)).all()
        responses = {r.alert_id: r for r in resp_rows}

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "Alert ID",
            "Source",
            "Severity",
            "Asset",
            "IOC List",
            "MITRE",
            "Description",
            "Triage Decision",
            "Risk Level",
            "Attack Type",
            "Confidence",
            "Created At",
        ]
    )

    for alert in alerts:
        resp = responses.get(alert.id)
        writer.writerow(
            [
                _csv_safe_cell(alert.id),
                _csv_safe_cell(alert.alert_source),
                _csv_safe_cell(alert.severity),
                _csv_safe_cell(alert.affected_asset),
                _csv_safe_cell(alert.ioc_list),
                _csv_safe_cell(alert.mitre_mapping),
                _csv_safe_cell((alert.raw_alert[:200] if alert.raw_alert else "")),
                _csv_safe_cell(resp.triage_decision if resp else ""),
                _csv_safe_cell(resp.risk_level if resp else ""),
                _csv_safe_cell(resp.attack_type if resp else ""),
                _csv_safe_cell(f"{resp.confidence_score:.2f}" if resp and resp.confidence_score is not None else ""),
                _csv_safe_cell(alert.created_at.isoformat() if alert.created_at else ""),
            ]
        )

    output.seek(0)
    filename = f"soc_alerts_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"

    write_audit_log(
        db,
        "alerts_csv_exported",
        {
            "exported_by": current_user.username,
            "role": current_user.role,
            "limit": limit,
            "exported_count": len(alerts),
        },
        user_id=current_user.user_id,
    )

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/alert/{alert_id}/pdf")
def export_alert_pdf(
    alert_id: str,
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db),
):
    try:
        from fpdf import FPDF
    except ImportError:
        raise HTTPException(status_code=500, detail="fpdf2 not installed: pip install fpdf2")

    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    resp = db.query(AlertResponse).filter(AlertResponse.alert_id == alert_id).first()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    use_unicode = try_register_unicode_fonts(pdf)

    def safe(text):
        return pdf_safe_unicode(text) if use_unicode else pdf_safe_latin1(text)

    FONT_FAMILY = "DejaVu" if use_unicode else "Helvetica"

    def reset_x():
        pdf.set_x(pdf.l_margin)

    def section_header(title: str):
        pdf.set_font(FONT_FAMILY, "B", 11)
        pdf.set_text_color(30, 64, 175)
        pdf.set_fill_color(239, 246, 255)
        reset_x()
        pdf.cell(0, 8, safe(f"  {title}"), new_x="LMARGIN", new_y="NEXT", fill=True)
        pdf.set_text_color(30, 30, 30)
        pdf.ln(2)

    def kv(key: str, value: str):
        pdf.set_font(FONT_FAMILY, "B", 9)
        pdf.set_text_color(80, 80, 80)
        reset_x()
        pdf.cell(0, 5, safe(f"{key}"), new_x="LMARGIN", new_y="NEXT")

        pdf.set_font(FONT_FAMILY, "", 9)
        pdf.set_text_color(20, 20, 20)
        reset_x()

        val = safe(value or "-")
        max_len = 110
        chunks = [val[i : i + max_len] for i in range(0, len(val), max_len)] or ["-"]
        for chunk in chunks:
            pdf.cell(0, 6, chunk, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    def body_text(text: str):
        pdf.set_font(FONT_FAMILY, "", 9)
        pdf.set_text_color(40, 40, 40)
        reset_x()
        pdf.multi_cell(0, 5.5, safe(text or "-"))
        pdf.ln(2)

    def bullet_list(items):
        pdf.set_font(FONT_FAMILY, "", 9)
        pdf.set_text_color(40, 40, 40)
        for i, item in enumerate(items, 1):
            reset_x()
            pdf.multi_cell(0, 5.5, safe(f"{i}. {item}"))
        pdf.ln(2)

    # Title
    pdf.set_font(FONT_FAMILY, "B", 18)
    pdf.set_text_color(30, 64, 175)
    reset_x()
    pdf.cell(
        0,
        12,
        safe("SOC ASSISTANT - INCIDENT REPORT"),
        new_x="LMARGIN",
        new_y="NEXT",
        align="C",
    )

    pdf.set_font(FONT_FAMILY, "", 9)
    pdf.set_text_color(100, 100, 100)
    reset_x()
    pdf.cell(
        0,
        6,
        safe(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')} | "
            f"Alert ID: {alert_id[:16]} | Exported by: {current_user.username}"
        ),
        new_x="LMARGIN",
        new_y="NEXT",
        align="C",
    )
    pdf.ln(4)

    pdf.set_draw_color(59, 130, 246)
    pdf.set_line_width(0.5)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(6)

    # Content
    section_header("ALERT INFORMATION")
    kv("Source", alert.alert_source)
    kv("Severity", alert.severity)
    kv("Asset", alert.affected_asset)
    kv("IOC List", alert.ioc_list or "None")
    kv("MITRE", alert.mitre_mapping or "Not mapped")
    kv("Timestamp", alert.created_at.strftime("%Y-%m-%d %H:%M UTC") if alert.created_at else "-")

    section_header("ALERT DESCRIPTION")
    body_text(alert.raw_alert)

    if resp:
        section_header("AI TRIAGE RESULT")
        kv("Decision", (resp.triage_decision or "").upper())
        kv("Risk Level", resp.risk_level or "-")
        kv("Attack Type", resp.attack_type or "-")
        kv("Confidence", f"{int((resp.confidence_score or 0) * 100)}%" if resp.confidence_score else "-")

        section_header("AI ANALYSIS EXPLANATION")
        body_text(resp.explanation)

        if resp.recommended_actions:
            section_header("RECOMMENDED ACTIONS")
            bullet_list(resp.recommended_actions)

        if resp.playbook:
            section_header("RESPONSE PLAYBOOK")
            # Keep readable while not destroying code blocks completely
            clean = (resp.playbook or "").replace("**", "")
            # Strip leading markdown heading markers only
            clean = "\n".join([ln.lstrip("#").strip() for ln in clean.splitlines()])
            body_text(clean[:3000])

        if resp.follow_up_questions:
            section_header("FOLLOW-UP QUESTIONS")
            bullet_list(resp.follow_up_questions)

        if resp.source_citations:
            section_header("SOURCE CITATIONS")
            bullet_list(resp.source_citations)

    # Footer
    pdf.set_y(-20)
    pdf.set_font(FONT_FAMILY, "", 8)
    pdf.set_text_color(150, 150, 150)
    reset_x()
    pdf.cell(
        0,
        8,
        safe("CONFIDENTIAL - SOC Assistant AI Report - For Internal Use Only"),
        align="C",
    )

    # Output bytes (fpdf2 quirk handling)
    try:
        pdf_bytes = bytes(pdf.output(dest="S"))
    except TypeError:
        raw = pdf.output(dest="S")
        pdf_bytes = raw.encode("latin-1") if isinstance(raw, str) else bytes(raw)

    filename = f"incident_{alert_id[:8]}_{datetime.utcnow().strftime('%Y%m%d')}.pdf"

    write_audit_log(
        db,
        "alert_pdf_exported",
        {
            "exported_by": current_user.username,
            "role": current_user.role,
            "alert_id": alert_id,
            "unicode_pdf": use_unicode,
        },
        user_id=current_user.user_id,
    )

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )