"""Semantic retrieval: security rule -> embedding -> Top-K code units.

Retrieval is CANDIDATE GENERATION only. It answers "which code appears
relevant to this requirement?", never "is this code vulnerable?" — that
judgment belongs to the LLM reasoning layer.
"""

from __future__ import annotations

from embeddings.embedder import EmbeddingModel
from models.schemas import RetrievedUnit, SecurityRule
from vector_store.chroma_store import ChromaStore


class Retriever:
    def __init__(self, embedder: EmbeddingModel, store: ChromaStore) -> None:
        self.embedder = embedder
        self.store = store

    def retrieve(self, rule: SecurityRule, top_k: int = 8) -> list[RetrievedUnit]:
        query_embedding = self.embedder.embed_queries([rule.render()])[0]
        return self.store.query(query_embedding, top_k=top_k)
