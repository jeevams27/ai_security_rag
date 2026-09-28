"""Indexing pipeline:

Repository -> discover files -> detect language -> Tree-sitter parse ->
semantic code units -> embeddings -> vector database.

The repository is indexed ONCE; all security rules then query the same
vector database. A manifest keyed on file content hashes skips re-embedding
files that have not changed.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from embeddings.embedder import EmbeddingModel
from vector_store.chroma_store import ChromaStore
from .file_discovery import discover_source_files, discover_unsupported_files
from .language_detector import detect_language
from .semantic_chunker import SemanticChunker


@dataclass
class IndexStats:
    files: int = 0
    lines: int = 0
    languages: dict[str, int] = field(default_factory=dict)
    code_units: int = 0
    embeddings: int = 0
    vector_records: int = 0
    files_reused_from_cache: int = 0
    files_skipped: int = 0
    skipped_files: list[str] = field(default_factory=list)
    runtime_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "files": self.files,
            "lines": self.lines,
            "languages": self.languages,
            "code_units": self.code_units,
            "embeddings": self.embeddings,
            "vector_records": self.vector_records,
            "files_reused_from_cache": self.files_reused_from_cache,
            "files_skipped": self.files_skipped,
            "skipped_files": self.skipped_files,
            "runtime_seconds": round(self.runtime_seconds, 3),
        }


class Indexer:
    def __init__(self, embedder: EmbeddingModel, store: ChromaStore,
                 chunker: SemanticChunker | None = None,
                 max_file_bytes: int = 1_000_000) -> None:
        self.embedder = embedder
        self.store = store
        self.chunker = chunker or SemanticChunker()
        self.max_file_bytes = max_file_bytes
        self._manifest_path = Path(store.persist_dir) / "manifest.json"

    # -- manifest (cache) ------------------------------------------------
    def _load_manifest(self) -> dict:
        if self._manifest_path.exists():
            try:
                return json.loads(self._manifest_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save_manifest(self, manifest: dict) -> None:
        self._manifest_path.write_text(
            json.dumps(manifest, indent=2), encoding="utf-8")

    @staticmethod
    def _file_hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    # -- main entry point -------------------------------------------------
    def index_repository(self, root: str | Path) -> IndexStats:
        start = time.time()
        root = Path(root)
        stats = IndexStats()
        manifest = self._load_manifest()
        skipped = discover_unsupported_files(root)
        stats.files_skipped = len(skipped)
        stats.skipped_files = [p.relative_to(root).as_posix() for p in skipped][:50]
        # The cache is only valid for the same embedding model.
        embedder_key = f"{self.embedder.name}"
        if manifest.get("__embedder__") != embedder_key:
            old_ids = [uid for entry in manifest.values() if isinstance(entry, dict)
                       for uid in entry.get("unit_ids", [])]
            self.store.delete(old_ids)
            manifest = {"__embedder__": embedder_key}

        new_manifest: dict = {"__embedder__": embedder_key}
        seen_files: set[str] = set()

        for path in discover_source_files(root, self.max_file_bytes):
            rel = path.relative_to(root).as_posix()
            language = detect_language(path)
            if language is None:
                continue
            seen_files.add(rel)
            stats.files += 1
            stats.lines += path.read_text(encoding="utf-8", errors="replace").count("\n") + 1
            stats.languages[language] = stats.languages.get(language, 0) + 1

            file_hash = self._file_hash(path)
            cached = manifest.get(rel)
            if cached and cached.get("hash") == file_hash:
                new_manifest[rel] = cached
                stats.code_units += len(cached.get("unit_ids", []))
                stats.files_reused_from_cache += 1
                continue

            if cached:  # file changed: drop stale units
                self.store.delete(cached.get("unit_ids", []))

            units = self.chunker.chunk_file(path, rel, language)
            embeddings = self.embedder.embed_texts([u.embedding_text() for u in units])
            self.store.add(units, embeddings)
            new_manifest[rel] = {"hash": file_hash,
                                 "unit_ids": [u.id for u in units]}
            stats.code_units += len(units)
            stats.embeddings += len(embeddings)

        # remove units for files that disappeared
        for rel, entry in manifest.items():
            if rel == "__embedder__" or rel in seen_files or not isinstance(entry, dict):
                continue
            self.store.delete(entry.get("unit_ids", []))

        self._save_manifest(new_manifest)
        stats.vector_records = self.store.count()
        stats.runtime_seconds = time.time() - start
        return stats
