"""
RAG Retriever
ChromaDB 0.5.15 — Hardened Version
"""
import os
import shutil
from typing import List, Dict, Optional
from pathlib import Path

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


class RAGRetriever:
    """
    Semantic search retriever using ChromaDB + SentenceTransformers.
    Compatible with chromadb==0.5.15
    """

    COLLECTION_NAME = "soc_knowledge_base"

    def __init__(self):
        from sentence_transformers import SentenceTransformer
        self.embedding_model = SentenceTransformer(settings.embedding_model)
        self.chroma_client = None
        self.collection = None
        self._init_chroma()

    def _init_chroma(self):
        """
        Initialize ChromaDB with automatic corruption recovery.
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
                    f"[RAG Retriever] ChromaDB ready — "
                    f"{self.collection.count()} chunks (attempt {attempt})"
                )
                return

            except Exception as e:
                error_str = str(e).lower()
                logger.error(f"[RAG Retriever] Init attempt {attempt} failed: {e}")

                is_schema_error = any(x in error_str for x in [
                    "no such column",
                    "collections.topic",
                    "_type",
                    "keyerror",
                    "schema",
                    "no such table",
                    "migration"
                ])

                if is_schema_error and attempt < max_attempts:
                    logger.warning("[RAG Retriever] Schema error detected — wiping store and retrying...")
                    self._wipe_chroma_store()
                    continue

                if attempt == max_attempts:
                    logger.error("[RAG Retriever] All init attempts failed — falling back to in-memory")
                    self._init_empty_fallback()
                    return

    def _wipe_chroma_store(self):
        store_path = Path(settings.chroma_persist_dir)
        if store_path.exists():
            try:
                shutil.rmtree(store_path)
                logger.warning(f"[RAG Retriever] Wiped ChromaDB store: {store_path}")
            except Exception as e:
                logger.error(f"[RAG Retriever] Wipe failed: {e}")

        store_path.mkdir(parents=True, exist_ok=True)

    def _init_empty_fallback(self):
        try:
            import chromadb
            self.chroma_client = chromadb.EphemeralClient()
            self.collection = self.chroma_client.get_or_create_collection(
                name=self.COLLECTION_NAME
            )
            logger.warning(
                "[RAG Retriever] Using in-memory fallback — "
                "results will be empty until documents are re-ingested"
            )
        except Exception as e:
            logger.error(f"[RAG Retriever] In-memory fallback also failed: {e}")
            self.chroma_client = None
            self.collection = None

    def retrieve(
        self,
        query: str,
        top_k: int = None,
        filter_doc_type: Optional[str] = None
    ) -> List[Dict]:
        """
        Retrieve top-k semantically similar chunks from ChromaDB.
        """
        if self.collection is None:
            logger.warning("[RAG Retriever] Collection unavailable — returning empty")
            return []

        query = (query or "").strip()
        if not query:
            logger.warning("[RAG Retriever] Empty query supplied — returning empty")
            return []

        if top_k is None:
            top_k = settings.top_k_results

        try:
            total = self.collection.count()
        except Exception as e:
            logger.error(f"[RAG Retriever] count() failed: {e}")
            return []

        if total == 0:
            logger.warning("[RAG Retriever] Knowledge base is empty — ingest documents first")
            return []

        try:
            query_embedding = self.embedding_model.encode(
                [query],
                normalize_embeddings=True,
                show_progress_bar=False
            ).tolist()
        except Exception as e:
            logger.error(f"[RAG Retriever] Embedding generation failed: {e}")
            return []

        n_results = min(top_k, total)
        query_kwargs: Dict = {
            "query_embeddings": query_embedding,
            "n_results": n_results,
            "include": ["documents", "metadatas", "distances"]
        }

        if filter_doc_type:
            query_kwargs["where"] = {"doc_type": filter_doc_type}

        try:
            results = self.collection.query(**query_kwargs)

            docs = results.get("documents", [[]])[0]
            metas = results.get("metadatas", [[]])[0]
            dists = results.get("distances", [[]])[0]

            retrieved = []
            for doc, meta, dist in zip(docs, metas, dists):
                if not doc:
                    continue

                meta = meta or {}
                retrieved.append({
                    "text": doc,
                    "source": meta.get("source", "unknown"),
                    "doc_type": meta.get("doc_type", "unknown"),
                    "distance": round(float(dist), 4) if dist is not None else None
                })

            logger.info(
                f"[RAG Retriever] Retrieved {len(retrieved)} chunks "
                f"for query: '{query[:50]}'"
            )
            return retrieved

        except Exception as e:
            logger.error(f"[RAG Retriever] Query failed: {e}")
            return []

    def format_context(self, results: List[Dict]) -> str:
        """
        Format retrieved chunks into a clean context block for LLM prompts.
        """
        if not results:
            return "No relevant context found in knowledge base."

        parts = []
        for i, r in enumerate(results, 1):
            text = r.get("text", "")
            source = r.get("source", "unknown")
            doc_type = r.get("doc_type", "unknown")

            if not text:
                continue

            parts.append(
                f"[Source {i}: {source} | Type: {doc_type}]\n{text}"
            )

        return "\n\n---\n\n".join(parts) if parts else "No relevant context found in knowledge base."

    def retrieve_for_alert(self, alert_data: Dict) -> str:
        """
        Multi-query retrieval specifically tuned for security alert triage.
        """
        queries = []

        mitre = str(alert_data.get("mitre_mapping", "")).strip()
        iocs = str(alert_data.get("ioc_list", "")).strip()
        description = str(alert_data.get("description", "")).strip()
        severity = str(alert_data.get("severity", "HIGH")).strip()
        source = str(alert_data.get("alert_source", "SIEM")).strip()

        if mitre:
            queries.append(mitre)
        if iocs:
            queries.append(iocs)
        if description:
            queries.append(description)

        queries.append(f"{severity} {source} security incident")

        seen: Dict[str, Dict] = {}

        for query in queries:
            results = self.retrieve(query, top_k=3)
            for r in results:
                text = r.get("text", "")
                if not text:
                    continue
                key = text[:100]
                if key not in seen:
                    seen[key] = r

        merged = list(seen.values())[:settings.top_k_results]
        return self.format_context(merged)