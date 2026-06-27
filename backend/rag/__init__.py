"""
RAG Pipeline Package
Retrieval-Augmented Generation for security knowledge.

Components:
- RAGIngestion  → Document chunking + embedding + ChromaDB storage
- RAGRetriever  → Semantic search & context formatting
- Embedder      → SentenceTransformer wrapper for embeddings
"""

from backend.rag.ingestion import RAGIngestion
from backend.rag.retriever import RAGRetriever
from backend.rag.embedder import Embedder

__all__ = ["RAGIngestion", "RAGRetriever", "Embedder"]