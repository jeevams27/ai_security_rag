import hashlib
import math
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from embeddings.embedder import EmbeddingModel  # noqa: E402
from vector_store.chroma_store import ChromaStore  # noqa: E402


class OfflineEmbedder(EmbeddingModel):
    """TEST-ONLY deterministic embedder (signed feature hashing).

    Keeps the test suite fully offline. Production always uses the local
    sentence-transformers model — tests only need *a* consistent vector space.
    """

    _TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[^\sA-Za-z0-9_]")

    def __init__(self, dim: int = 384) -> None:
        self.name = f"offline-test:{dim}"
        self.dim = dim

    def _features(self, text: str) -> list[str]:
        tokens = self._TOKEN_RE.findall(text.lower())
        feats = [f"tok:{t}" for t in tokens]
        feats += [f"bi:{tokens[i]}_{tokens[i+1]}" for i in range(len(tokens) - 1)]
        for t in tokens:
            for n in (3, 4):
                feats += [f"ch{n}:{t[i:i+n]}" for i in range(max(0, len(t) - n + 1))]
        return feats

    def embed_texts(self, texts: list[str]) -> list[list[float]]:
        vectors: list[list[float]] = []
        for text in texts:
            vec = [0.0] * self.dim
            for feat in self._features(text):
                digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
                value = int.from_bytes(digest, "little")
                idx = value % self.dim
                sign = 1.0 if (value >> 63) & 1 == 0 else -1.0
                vec[idx] += sign
            norm = math.sqrt(sum(v * v for v in vec)) or 1.0
            vectors.append([v / norm for v in vec])
        return vectors


@pytest.fixture()
def embedder():
    # Offline deterministic embedder: no model download, no API calls.
    return OfflineEmbedder(dim=128)


@pytest.fixture()
def store(tmp_path):
    return ChromaStore(persist_dir=str(tmp_path / "chroma"),
                       collection_name="test_units")


class FakeLLM:
    """Offline LLM stub returning canned strict-JSON responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = 0

    def chat(self, messages):
        from llm.openrouter_client import LLMResponse

        self.calls += 1
        content = self._responses.pop(0) if self._responses else "{}"
        return LLMResponse(content=content, prompt_tokens=10,
                           completion_tokens=5, total_tokens=15)
