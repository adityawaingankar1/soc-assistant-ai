# backend/rag/ingestion.py
"""
RAG Ingestion Pipeline
ChromaDB 0.5.15 — Updated for user/document-level deletion support
"""

import os
import shutil
from pathlib import Path
from typing import List, Dict, Optional
import uuid

from loguru import logger
from backend.config import get_settings

settings = get_settings()


def _make_chroma_client():
    """
    Create a ChromaDB PersistentClient with telemetry disabled.
    """
    import chromadb
    from chromadb.config import Settings as ChromaSettings

    os.makedirs(settings.chroma_persist_dir, exist_ok=True)

    return chromadb.PersistentClient(
        path=settings.chroma_persist_dir,
        settings=ChromaSettings(
            anonymized_telemetry=False,
            allow_reset=True
        )
    )


def _make_splitter():
    """
    Create text splitter.
    Falls back to a manual chunker if langchain is not installed.
    """
    try:
        from langchain_text_splitters import RecursiveCharacterTextSplitter
        return RecursiveCharacterTextSplitter(
            chunk_size=settings.chunk_size,
            chunk_overlap=settings.chunk_overlap,
            length_function=len,
            separators=["\n\n", "\n", ". ", " ", ""]
        )
    except ImportError:
        logger.warning(
            "[RAG Ingestion] langchain_text_splitters not found — using manual chunker"
        )
        return None


class RAGIngestion:
    """
    Document ingestion pipeline for the SOC RAG system.
    Compatible with chromadb==0.5.15
    """

    COLLECTION_NAME = "soc_knowledge_base"

    def __init__(self):
        from sentence_transformers import SentenceTransformer

        self.embedding_model = SentenceTransformer(settings.embedding_model)
        self.text_splitter = _make_splitter()

        self.chroma_client = None
        self.collection = None

        self._init_chroma()

        count = self.collection.count() if self.collection else 0
        logger.info(
            f"[RAG Ingestion] Ready — {count} chunks in knowledge base"
        )

    def _init_chroma(self):
        """
        Initialize ChromaDB with automatic corruption recovery.
        Retries up to 3 times, wiping the store on schema errors.
        """
        max_attempts = 3

        for attempt in range(1, max_attempts + 1):
            try:
                self.chroma_client = _make_chroma_client()
                self.collection = self.chroma_client.get_or_create_collection(
                    name=self.COLLECTION_NAME,
                    metadata={"hnsw:space": "cosine"}
                )
                logger.info(
                    f"[RAG Ingestion] ChromaDB initialized — attempt {attempt}/{max_attempts}"
                )
                return

            except Exception as e:
                error_str = str(e).lower()
                logger.error(f"[RAG Ingestion] Init attempt {attempt} failed: {e}")

                is_schema_error = any(x in error_str for x in [
                    "no such column",
                    "collections.topic",
                    "_type",
                    "keyerror",
                    "schema",
                    "migration",
                    "no such table"
                ])

                if is_schema_error and attempt < max_attempts:
                    logger.warning(
                        "[RAG Ingestion] Schema mismatch — wiping ChromaDB store and retrying..."
                    )
                    self._wipe_chroma_store()
                    continue

                if attempt == max_attempts:
                    logger.error(
                        "[RAG Ingestion] All attempts failed — falling back to in-memory ChromaDB"
                    )
                    self._init_memory_fallback()
                    return

    def _wipe_chroma_store(self):
        """
        Completely delete the ChromaDB persist directory.
        """
        store_path = Path(settings.chroma_persist_dir)
        if store_path.exists():
            try:
                shutil.rmtree(store_path)
                logger.warning(f"[RAG Ingestion] Wiped ChromaDB store: {store_path}")
            except Exception as e:
                logger.error(f"[RAG Ingestion] Wipe failed: {e}")

        store_path.mkdir(parents=True, exist_ok=True)

    def _init_memory_fallback(self):
        """
        Use an in-memory ChromaDB as last resort.
        """
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings

            logger.warning(
                "[RAG Ingestion] Using IN-MEMORY ChromaDB — data will not persist across restarts"
            )

            self.chroma_client = chromadb.EphemeralClient(
                settings=ChromaSettings(anonymized_telemetry=False)
            )
            self.collection = self.chroma_client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"}
            )
            logger.info("[RAG Ingestion] In-memory fallback ready")

        except Exception as e:
            logger.error(f"[RAG Ingestion] In-memory fallback failed: {e}")
            self.chroma_client = None
            self.collection = None

    def _chunk_text(self, text: str) -> List[str]:
        """
        Split text into overlapping chunks.
        """
        if self.text_splitter:
            return self.text_splitter.split_text(text)

        chunks = []
        chunk_size = settings.chunk_size
        overlap = settings.chunk_overlap
        start = 0

        while start < len(text):
            end = start + chunk_size
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            start = end - overlap
            if start >= len(text):
                break

        return chunks

    def ingest_text(
        self,
        text: str,
        source: str,
        doc_type: str,
        metadata: Optional[Dict] = None
    ) -> int:
        """
        Chunk, embed, and store text in ChromaDB.

        Args:
            text: Raw document text
            source: Source filename or unique document label
            doc_type: mitre_attack | runbook | incident_history | cve_database | user_upload
            metadata: Extra metadata to persist with every chunk, e.g.
                      {
                          "document_id": "...",
                          "uploaded_by_user_id": "...",
                          "uploaded_by_username": "...",
                          "filename": "..."
                      }

        Returns:
            Number of chunks stored
        """
        if not text or not text.strip():
            logger.warning(f"[RAG Ingestion] Empty text from '{source}' — skipping")
            return 0

        if self.collection is None:
            logger.error("[RAG Ingestion] Collection unavailable — cannot ingest")
            return 0

        chunks = self._chunk_text(text)
        if not chunks:
            logger.warning(f"[RAG Ingestion] No chunks produced from '{source}'")
            return 0

        try:
            embeddings = self.embedding_model.encode(
                chunks,
                batch_size=32,
                show_progress_bar=False,
                normalize_embeddings=True
            ).tolist()
        except Exception as e:
            logger.error(f"[RAG Ingestion] Embedding failed for '{source}': {e}")
            return 0

        ids = [str(uuid.uuid4()) for _ in chunks]

        base_metadata = {
            "source": str(source),
            "doc_type": str(doc_type),
        }
        if metadata:
            base_metadata.update(metadata)

        metadatas = [
            {
                **base_metadata,
                "chunk_index": i,
                "chunk_total": len(chunks)
            }
            for i in range(len(chunks))
        ]

        batch_size = 100
        stored_total = 0

        for i in range(0, len(chunks), batch_size):
            batch_end = i + batch_size
            try:
                self.collection.add(
                    documents=chunks[i:batch_end],
                    embeddings=embeddings[i:batch_end],
                    ids=ids[i:batch_end],
                    metadatas=metadatas[i:batch_end]
                )
                stored_total += len(chunks[i:batch_end])
            except Exception as e:
                logger.error(
                    f"[RAG Ingestion] Batch {i}-{batch_end} failed for '{source}': {e}"
                )
                break

        logger.info(
            f"[RAG Ingestion] ✅ '{source}' ({doc_type}): "
            f"{stored_total}/{len(chunks)} chunks stored"
        )
        return stored_total

    def ingest_file(self, file_path: str, doc_type: str) -> int:
        """Ingest a .txt or .md file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        return self.ingest_text(text, path.name, doc_type)

    def ingest_pdf(self, file_path: str, doc_type: str) -> int:
        """Ingest a PDF file."""
        try:
            import PyPDF2
        except ImportError:
            raise ImportError("Install PyPDF2: pip install PyPDF2")

        text = ""
        with open(file_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                extracted = page.extract_text()
                if extracted:
                    text += extracted + "\n\n"

        if not text.strip():
            raise ValueError(f"No text extracted from PDF: {file_path}")

        return self.ingest_text(text, Path(file_path).name, doc_type)

    def load_sample_knowledge_base(self) -> int:
        """
        Load all sample security documents into ChromaDB on startup.
        Skips loading if the knowledge base already has documents.
        """
        if self.collection is None:
            logger.error("[RAG Ingestion] Collection unavailable — cannot load KB")
            return 0

        current_count = self.collection.count()
        if current_count > 0:
            logger.info(
                f"[RAG Ingestion] Knowledge base already has {current_count} chunks — skipping reload"
            )
            return current_count

        sample_dir = Path("backend/sample_data")
        if not sample_dir.exists():
            logger.warning(
                f"[RAG Ingestion] Sample data directory not found: {sample_dir}\n"
                "Create backend/sample_data/ with: mitre_snippets.txt, runbooks.txt, past_incidents.txt, cve_database.txt"
            )
            return 0

        doc_map = {
            "mitre_snippets.txt": "mitre_attack",
            "runbooks.txt": "runbook",
            "past_incidents.txt": "incident_history",
            "cve_database.txt": "cve_database"
        }

        total = 0
        for filename, doc_type in doc_map.items():
            filepath = sample_dir / filename
            if filepath.exists():
                try:
                    count = self.ingest_file(str(filepath), doc_type)
                    total += count
                except Exception as e:
                    logger.error(f"[RAG Ingestion] Failed to load '{filename}': {e}")
            else:
                logger.warning(f"[RAG Ingestion] Sample file missing: {filepath}")

        logger.info(f"[RAG Ingestion] ✅ Knowledge base loaded: {total} total chunks")
        return total

    def reset_collection(self) -> bool:
        """
        Delete and recreate the ChromaDB collection.
        """
        logger.warning("[RAG Ingestion] Resetting collection...")

        try:
            self.chroma_client.delete_collection(self.COLLECTION_NAME)
            self.collection = self.chroma_client.get_or_create_collection(
                name=self.COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"}
            )
            logger.info("[RAG Ingestion] ✅ Soft reset successful")
            return True
        except Exception as e:
            logger.error(f"[RAG Ingestion] Soft reset failed: {e}")

        try:
            self._wipe_chroma_store()
            self._init_chroma()
            logger.info("[RAG Ingestion] ✅ Hard reset successful")
            return True
        except Exception as e2:
            logger.error(f"[RAG Ingestion] Hard reset failed: {e2}")
            return False

    def get_stats(self) -> Dict:
        """Return knowledge base statistics."""
        try:
            count = self.collection.count() if self.collection else 0
        except Exception:
            count = 0

        return {
            "total_chunks": count,
            "persist_dir": settings.chroma_persist_dir,
            "embedding_model": settings.embedding_model,
            "chunk_size": settings.chunk_size,
            "chunk_overlap": settings.chunk_overlap,
            "collection_name": self.COLLECTION_NAME
        }

    def delete_by_source(self, source: str) -> int:
        """
        Delete all chunks for a specific source from ChromaDB.
        Returns number of chunks deleted.
        """
        if self.collection is None:
            logger.error("[RAG Ingestion] Collection unavailable — cannot delete source")
            return 0

        try:
            results = self.collection.get(where={"source": str(source)})
            ids = results.get("ids", []) if results else []
            if not ids:
                return 0

            self.collection.delete(ids=ids)
            logger.info(f"[RAG Ingestion] Deleted {len(ids)} chunk(s) for source '{source}'")
            return len(ids)
        except Exception as e:
            logger.error(f"[RAG Ingestion] Failed deleting source '{source}': {e}")
            return 0

    def delete_by_document_id(self, document_id: str) -> int:
        """
        Delete all chunks for a specific document_id from ChromaDB.
        Returns number of chunks deleted.
        """
        if self.collection is None:
            logger.error("[RAG Ingestion] Collection unavailable — cannot delete document")
            return 0

        try:
            results = self.collection.get(where={"document_id": str(document_id)})
            ids = results.get("ids", []) if results else []
            if not ids:
                return 0

            self.collection.delete(ids=ids)
            logger.info(
                f"[RAG Ingestion] Deleted {len(ids)} chunk(s) for document_id '{document_id}'"
            )
            return len(ids)
        except Exception as e:
            logger.error(f"[RAG Ingestion] Failed deleting document_id '{document_id}': {e}")
            return 0

    def delete_by_user_id(self, user_id: str) -> int:
        """
        Delete all chunks uploaded by a specific user from ChromaDB.
        Returns number of chunks deleted.
        """
        if self.collection is None:
            logger.error("[RAG Ingestion] Collection unavailable — cannot delete user data")
            return 0

        try:
            results = self.collection.get(where={"uploaded_by_user_id": str(user_id)})
            ids = results.get("ids", []) if results else []
            if not ids:
                return 0

            self.collection.delete(ids=ids)
            logger.info(
                f"[RAG Ingestion] Deleted {len(ids)} chunk(s) for user_id '{user_id}'"
            )
            return len(ids)
        except Exception as e:
            logger.error(f"[RAG Ingestion] Failed deleting user_id '{user_id}': {e}")
            return 0