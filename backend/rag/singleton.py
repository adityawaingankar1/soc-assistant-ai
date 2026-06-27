# backend/rag/singleton.py
"""
Singleton instances for RAG components.
Ensures RAGIngestion and RAGRetriever are created only once per process.
"""

from functools import lru_cache


@lru_cache(maxsize=1)
def get_ingestion():
    """Return the single RAGIngestion instance."""
    from backend.rag.ingestion import RAGIngestion
    return RAGIngestion()


@lru_cache(maxsize=1)
def get_retriever():
    """Return the single RAGRetriever instance."""
    from backend.rag.retriever import RAGRetriever
    return RAGRetriever()