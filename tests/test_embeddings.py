"""Embedding layer tests: the vector-space contract, the offline test
embedder, and the create_embedder factory (no model download)."""

import embeddings.embedder as embedder_module
from embeddings.embedder import EmbeddingModel, create_embedder
from tests.conftest import OfflineEmbedder


def test_embed_queries_uses_the_same_space_as_texts():
    """Rules and code MUST be embedded by the same model."""

    class Recording(EmbeddingModel):
        def __init__(self):
            self.scored = []

        def embed_texts(self, texts):
            self.scored.extend(texts)
            return [[1.0, 0.0] for _ in texts]

    emb = Recording()
    emb.embed_queries(["rule text"])
    assert emb.scored == ["rule text"]


def test_offline_embedder_deterministic_and_normalized():
    emb = OfflineEmbedder(dim=64)
    v1 = emb.embed_texts(["def update_user(): pass"])[0]
    v2 = emb.embed_texts(["def update_user(): pass"])[0]
    assert v1 == v2
    assert len(v1) == 64
    norm = sum(x * x for x in v1) ** 0.5
    assert abs(norm - 1.0) < 1e-6


def test_offline_embedder_similar_texts_closer():
    emb = OfflineEmbedder(dim=512)
    a = emb.embed_texts(["user input concatenated into sql query execute"])[0]
    b = emb.embed_texts(["sql query built from user input concatenation"])[0]
    c = emb.embed_texts(["renders html template for the home page"])[0]

    def dot(x, y):
        return sum(i * j for i, j in zip(x, y))

    assert dot(a, b) > dot(a, c)


def test_create_embedder_builds_the_local_model(monkeypatch):
    """The factory uses EMBEDDING_MODEL with the local ST embedder."""
    seen = {}

    class FakeST(EmbeddingModel):
        def __init__(self, model_name="all-MiniLM-L6-v2"):
            seen["model_name"] = model_name
            self.name = f"sentence_transformers:{model_name}"
            self.dim = 384

        def embed_texts(self, texts):
            return [[0.0] * self.dim for _ in texts]

    monkeypatch.setattr(embedder_module, "SentenceTransformerEmbedder", FakeST)

    class Cfg:
        embedding_model = "all-MiniLM-L6-v2"

    emb = create_embedder(Cfg())
    assert seen["model_name"] == "all-MiniLM-L6-v2"
    assert emb.dim == 384


def test_create_embedder_reports_missing_dependency(monkeypatch):
    def boom(model_name="all-MiniLM-L6-v2"):
        raise ImportError("no sentence_transformers")

    monkeypatch.setattr(embedder_module, "SentenceTransformerEmbedder", boom)

    class Cfg:
        embedding_model = "all-MiniLM-L6-v2"

    try:
        create_embedder(Cfg())
    except RuntimeError as exc:
        assert "sentence-transformers is not installed" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected RuntimeError")

