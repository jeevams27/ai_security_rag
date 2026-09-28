"""Embedding model abstraction.

The SAME embedding space is used for code units and security rules;
`embed_texts` and `embed_queries` must therefore come from one model.

Backend: `sentence_transformers` — a local model (default
`all-MiniLM-L6-v2`). No paid API required; the model is downloaded once
and then runs offline on CPU.
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class EmbeddingModel(ABC):
    name: str = "abstract"
    dim: int = 0

    @abstractmethod
    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        """Embed documents (code units)."""

    def embed_queries(self, texts: list[str]) -> list[list[float]]:
        """Embed queries (security rules). Same space as documents."""
        return self.embed_texts(texts)


class SentenceTransformerEmbedder(EmbeddingModel):
    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        from sentence_transformers import SentenceTransformer  # lazy import

        self._model = SentenceTransformer(model_name)
        self.name = f"sentence_transformers:{model_name}"
        get_dim = getattr(self._model, "get_embedding_dimension", None) or \
            getattr(self._model, "get_sentence_embedding_dimension")
        self.dim = int(get_dim())

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        return [
            [float(x) for x in vec]
            for vec in self._model.encode(list(texts), convert_to_numpy=True)
        ]


def create_embedder(config) -> EmbeddingModel:
    """Factory: build the local embedding model from configuration."""
    try:
        return SentenceTransformerEmbedder(config.embedding_model)
    except ImportError as exc:
        raise RuntimeError(
            "sentence-transformers is not installed. Install the project "
            "requirements (pip install -r requirements.txt) — it is the "
            "only embedding backend."
        ) from exc

