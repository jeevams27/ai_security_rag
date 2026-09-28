"""Offline benchmark demo: index benchmark/source with the real local
embedding model and print per-rule retrieval (no LLM calls)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from config import Config
from embeddings.embedder import create_embedder
from ingestion.indexer import Indexer
from json_io import load_rules_file
from models.schemas import SecurityRule
from retrieval.retriever import Retriever
from vector_store.chroma_store import ChromaStore

ROOT = Path(__file__).resolve().parent.parent


def main() -> None:
    cfg = Config.from_env()
    emb = create_embedder(cfg)
    print(f"embedder: {emb.name} dim={emb.dim}")
    store = ChromaStore(persist_dir=str(ROOT / ".chroma_bench"),
                        collection_name="bench")
    stats = Indexer(emb, store).index_repository(ROOT / "benchmark" / "source")
    print("INDEX:", json.dumps(stats.to_dict()))
    rules = [SecurityRule.from_dict(r) for r in load_rules_file(
        ROOT / "benchmark" / "security_rules.json")]
    retr = Retriever(emb, store)
    for rule in rules:
        print(f"\n--- {rule.rule_id} {rule.category}")
        for r in retr.retrieve(rule, top_k=5):
            u = r.unit
            print(f"  {r.score:.3f}  {u.file}:{u.start_line}-{u.end_line} "
                  f"{u.type} {u.symbol}")


if __name__ == "__main__":
    main()
