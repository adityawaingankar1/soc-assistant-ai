"""
Document Management Routes — with RBAC
Upload / Stats / Query / List → admin + analyst (+ stats/query/list visible to viewer)
Reset / Reload / Delete → admin only
"""
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, Query, Request
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
import tempfile
import os
import re
from datetime import datetime

from backend.database import get_db, KnowledgeBaseDocument
from backend.rag.singleton import get_ingestion
from backend.auth import TokenData, require_role
from backend.utils.audit import write_audit_log
from loguru import logger

router = APIRouter(prefix="/api", tags=["Document Management"])
logger.info("[Docs] routes_docs.py loaded with KB inventory routes")

MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


class KBQueryRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=1000)
    top_k: int = Field(3, ge=1, le=10)


def sanitize_filename(filename: str) -> str:
    filename = filename.strip()
    filename = os.path.basename(filename)
    filename = re.sub(r"[^a-zA-Z0-9._\- ]", "_", filename)
    return filename[:255]


def _scope_kb_documents_query(query, current_user: TokenData):
    """Admin sees all KB docs; others see only their own uploads."""
    if current_user.role == "admin":
        return query
    return query.filter(KnowledgeBaseDocument.uploaded_by_user_id == current_user.user_id)


@router.post("/upload-docs")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    doc_type: str = Form(...),
    current_user: TokenData = Depends(require_role("admin", "analyst")),
    db: Session = Depends(get_db)
):
    ingestion = get_ingestion()
    request_id = getattr(request.state, "request_id", None)

    allowed_types = ["mitre_attack", "runbook", "incident_history", "cve_database", "custom"]
    if doc_type not in allowed_types:
        raise HTTPException(status_code=400, detail=f"doc_type must be one of: {allowed_types}")

    allowed_extensions = [".txt", ".pdf", ".md"]
    raw_filename = file.filename or "uploaded_file"
    filename = sanitize_filename(raw_filename)
    ext = os.path.splitext(filename)[1].lower()

    if ext not in allowed_extensions:
        raise HTTPException(status_code=400, detail=f"File type not supported. Use: {allowed_extensions}")

    content = await file.read()
    file_size_bytes = len(content)

    if file_size_bytes == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    if file_size_bytes > MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB"
        )

    content_type = (file.content_type or "").lower()
    if ext == ".pdf" and "pdf" not in content_type and content_type not in ("application/octet-stream", ""):
        logger.warning(f"[Docs] Suspicious content-type for PDF upload: {content_type}")

    preview_text = ""

    with tempfile.NamedTemporaryFile(delete=False, suffix=ext) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        if ext == ".pdf":
            try:
                import PyPDF2
                with open(tmp_path, "rb") as f:
                    reader = PyPDF2.PdfReader(f)
                    extracted_preview = ""
                    for page in reader.pages[:2]:
                        text = page.extract_text()
                        if text:
                            extracted_preview += text + "\n"
                    preview_text = extracted_preview[:500]
            except Exception:
                preview_text = "[Preview unavailable for this PDF]"

            chunks = ingestion.ingest_pdf(tmp_path, doc_type)
        else:
            try:
                preview_text = content.decode("utf-8", errors="ignore")[:500]
            except Exception:
                preview_text = "[Preview unavailable]"
            chunks = ingestion.ingest_file(tmp_path, doc_type)

        kb_doc = KnowledgeBaseDocument(
            filename=filename,
            doc_type=doc_type,
            source=filename,
            uploaded_by_user_id=current_user.user_id,
            uploaded_by_username=current_user.username,
            file_size_bytes=file_size_bytes,
            chunks_ingested=chunks,
            preview_text=preview_text.strip() if preview_text else ""
        )
        db.add(kb_doc)
        db.commit()
        db.refresh(kb_doc)

        logger.info(
            f"[Docs] Upload by '{current_user.username}' — "
            f"{filename} ({doc_type}, {chunks} chunks, request_id={request_id})"
        )

        write_audit_log(
            db,
            "kb_document_uploaded",
            {
                "filename": filename,
                "doc_type": doc_type,
                "chunks_ingested": chunks,
                "file_size_bytes": file_size_bytes,
                "uploaded_by": current_user.username,
                "request_id": request_id
            },
            user_id=current_user.user_id
        )

        return {
            "success": True,
            "document": kb_doc.to_dict(),
            "uploaded_at": datetime.utcnow().isoformat(),
            "kb_stats": ingestion.get_stats(),
            "request_id": request_id
        }

    except Exception as e:
        logger.error(f"[Docs] Upload failed: {e} | request_id={request_id}")
        raise HTTPException(status_code=500, detail=f"Ingestion failed: {str(e)}")
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@router.get("/knowledge-base/stats")
def get_kb_stats(
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer"))
):
    return get_ingestion().get_stats()


@router.post("/knowledge-base/query")
def query_knowledge_base(
    req: KBQueryRequest,
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db)
):
    ingestion = get_ingestion()

    if not getattr(ingestion, "collection", None):
        raise HTTPException(status_code=500, detail="Knowledge base collection is unavailable.")

    try:
        query_embedding = ingestion.embedding_model.encode(
            [req.query],
            normalize_embeddings=True,
            show_progress_bar=False
        ).tolist()[0]

        results = ingestion.collection.query(
            query_embeddings=[query_embedding],
            n_results=req.top_k
        )

        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        ids = results.get("ids", [[]])[0]

        matches = []
        for doc, meta, _id in zip(docs, metas, ids):
            matches.append({
                "id": _id,
                "source": meta.get("source", "unknown") if meta else "unknown",
                "doc_type": meta.get("doc_type", "unknown") if meta else "unknown",
                "chunk_index": meta.get("chunk_index", 0) if meta else 0,
                "chunk_total": meta.get("chunk_total", 0) if meta else 0,
                "snippet": (doc[:500] + "...") if doc and len(doc) > 500 else (doc or "")
            })

        write_audit_log(
            db,
            "kb_query_executed",
            {
                "username": current_user.username,
                "role": current_user.role,
                "query": req.query[:200],
                "top_k": req.top_k,
                "matches_found": len(matches)
            },
            user_id=current_user.user_id
        )

        return {
            "success": True,
            "query": req.query,
            "top_k": req.top_k,
            "matches_found": len(matches),
            "matches": matches
        }

    except Exception as e:
        logger.error(f"[Docs] KB query failed: {e}")
        raise HTTPException(status_code=500, detail=f"Knowledge base query failed: {str(e)}")


@router.get("/knowledge-base/documents")
def list_kb_documents(
    search: str = Query("", max_length=200),
    doc_type: str = Query("", max_length=50),
    current_user: TokenData = Depends(require_role("admin", "analyst", "viewer")),
    db: Session = Depends(get_db)
):
    query = db.query(KnowledgeBaseDocument).order_by(KnowledgeBaseDocument.created_at.desc())
    query = _scope_kb_documents_query(query, current_user)

    if search:
        query = query.filter(KnowledgeBaseDocument.filename.ilike(f"%{search}%"))

    if doc_type:
        query = query.filter(KnowledgeBaseDocument.doc_type == doc_type)

    docs = query.all()

    return {
        "total": len(docs),
        "documents": [d.to_dict() for d in docs]
    }


@router.delete("/knowledge-base/documents/{doc_id}")
def delete_kb_document(
    doc_id: str,
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    ingestion = get_ingestion()

    doc = db.query(KnowledgeBaseDocument).filter(KnowledgeBaseDocument.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")

    deleted_chunks = ingestion.delete_by_source(doc.source)

    db.delete(doc)
    db.commit()

    logger.info(
        f"[Docs] Document deleted by '{current_user.username}' — "
        f"{doc.filename} ({deleted_chunks} chunks removed)"
    )

    write_audit_log(
        db,
        "kb_document_deleted",
        {
            "filename": doc.filename,
            "doc_id": doc_id,
            "deleted_chunks": deleted_chunks,
            "deleted_by": current_user.username
        },
        user_id=current_user.user_id
    )

    return {
        "success": True,
        "message": f"Deleted document '{doc.filename}'",
        "deleted_document_id": doc_id,
        "deleted_chunks": deleted_chunks,
        "stats": ingestion.get_stats()
    }


@router.post("/knowledge-base/reset")
def reset_knowledge_base(
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    try:
        success = get_ingestion().reset_collection()

        db.query(KnowledgeBaseDocument).delete()
        db.commit()

        logger.info(f"[Docs] KB reset by '{current_user.username}'")

        write_audit_log(
            db,
            "kb_reset",
            {
                "reset_by": current_user.username,
                "role": current_user.role,
                "success": success
            },
            user_id=current_user.user_id
        )

        return {
            "success": success,
            "message": "Reset successful" if success else "Reset failed",
            "reset_by": current_user.username,
            "stats": get_ingestion().get_stats()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/knowledge-base/reload")
def reload_knowledge_base(
    current_user: TokenData = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    try:
        get_ingestion().reset_collection()
        db.query(KnowledgeBaseDocument).delete()
        db.commit()

        count = get_ingestion().load_sample_knowledge_base()

        logger.info(
            f"[Docs] KB reloaded by '{current_user.username}' — "
            f"{count} chunks"
        )

        write_audit_log(
            db,
            "kb_reloaded",
            {
                "reloaded_by": current_user.username,
                "role": current_user.role,
                "chunks_loaded": count
            },
            user_id=current_user.user_id
        )

        return {
            "success": True,
            "chunks_loaded": count,
            "reloaded_by": current_user.username,
            "stats": get_ingestion().get_stats()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))