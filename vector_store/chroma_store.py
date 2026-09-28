"""Local persistent vector store backed by ChromaDB.

Stores, per code unit: embedding, source code (document), and metadata
(file, language, symbol, type, start_line, end_line). No cloud infra.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import chromadb

from models.schemas import CodeUnit, RetrievedUnit


class ChromaStore:
    def __init__(self, persist_dir: str = ".chroma",
                 collection_name: str = "code_units") -> None:
        self.persist_dir = persist_dir
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(path=persist_dir)
        self._collection = self._client.get_or_create_collection(
            name=collection_name, metadata={"hnsw:space": "cosine"}
        )

    def count(self) -> int:
        return self._collection.count()

    def add(self, units: list[CodeUnit], embeddings: list[list[float]]) -> None:
        if not units:
            return
        self._collection.upsert(
            ids=[u.id for u in units],
            embeddings=embeddings,
            documents=[u.code for u in units],
            metadatas=[u.to_metadata() for u in units],
        )

    def delete(self, ids: list[str]) -> None:
        if ids:
            self._collection.delete(ids=ids)

    def get(self, ids: list[str]) -> dict[str, Any]:
        return self._collection.get(ids=ids, include=["documents", "metadatas"])

    def query(self, embedding: list[float], top_k: int = 8,
              where: Optional[dict] = None) -> list[RetrievedUnit]:
        if self.count() == 0:
            return []
        top_k = max(1, min(top_k, self.count()))
        kwargs: dict[str, Any] = {}
        if where:
            kwargs["where"] = where
        result = self._collection.query(
            query_embeddings=[embedding], n_results=top_k,
            include=["documents", "metadatas", "distances"], **kwargs,
        )
        units: list[RetrievedUnit] = []
        ids = result.get("ids", [[]])[0]
        docs = result.get("documents", [[]])[0]
        metas = result.get("metadatas", [[]])[0]
        dists = result.get("distances", [[]])[0]
        for uid, doc, meta, dist in zip(ids, docs, metas, dists):
            unit = CodeUnit(
                file=meta["file"], language=meta["language"],
                symbol=meta["symbol"], type=meta["type"],
                start_line=int(meta["start_line"]), end_line=int(meta["end_line"]),
                code=doc, id=uid,
            )
            # cosine distance -> similarity
            units.append(RetrievedUnit(unit=unit, score=1.0 - float(dist)))
        return units
