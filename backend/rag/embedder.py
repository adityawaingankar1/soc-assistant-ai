"""
Embedder — sentence-transformers 2.7.0 Compatible
"""

from typing import List, Union
import numpy as np
from sentence_transformers import SentenceTransformer
from functools import lru_cache
from backend.config import get_settings
from loguru import logger

settings = get_settings()


class Embedder:
    """
    SentenceTransformer wrapper for text embeddings.
    Compatible with sentence-transformers==2.7.0
    """

    def __init__(self, model_name: str = None):
        model_name = model_name or settings.embedding_model
        logger.info(f"[Embedder] Loading: {model_name}")

        self.model = SentenceTransformer(model_name)
        self.model_name = model_name
        self.embedding_dim = self.model.get_sentence_embedding_dimension()

        logger.info(f"[Embedder] ✅ Ready — dim={self.embedding_dim}")

    def embed(self, text: Union[str, List[str]]) -> np.ndarray:
        """Embed one or more strings. Returns numpy array."""
        if isinstance(text, str):
            text = [text]

        return self.model.encode(
            text,
            normalize_embeddings=True,
            show_progress_bar=False
        )

    def embed_single(self, text: str) -> List[float]:
        """Embed a single string. Returns list of floats."""
        return self.embed(text)[0].tolist()

    def embed_batch(self, texts: List[str], batch_size: int = 32) -> List[List[float]]:
        """Embed a batch efficiently. Returns list of float lists."""
        return self.model.encode(
            texts,
            batch_size=batch_size,
            normalize_embeddings=True,
            show_progress_bar=len(texts) > 100
        ).tolist()

    def cosine_similarity(
        self,
        emb1: List[float],
        emb2: List[float]
    ) -> float:
        """Cosine similarity between two embeddings."""
        a, b = np.array(emb1), np.array(emb2)
        return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b)))

    def get_info(self) -> dict:
        """Model metadata."""
        return {
            "model_name": self.model_name,
            "embedding_dimensions": self.embedding_dim,
            "max_sequence_length": self.model.max_seq_length,
        }


@lru_cache(maxsize=1)
def get_embedder() -> Embedder:
    """Singleton embedder — model loads only once per process."""
    return Embedder()