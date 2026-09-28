"""Live integration test against OpenRouter.

Indexes the benchmark repository, loads security_rules.json, performs
semantic retrieval, sends ONLY the retrieved context to the LLM, parses
the response, validates evidence, and prints the final verdict.

Usage:
    set OPENROUTER_API_KEY=...
    set OPENROUTER_MODEL=openai/gpt-4o-mini   # optional, has a default
    python scripts/live_test.py
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from analysis.evidence_validator import EvidenceValidator
from analysis.analyzer import SecurityAnalyzer
from config import Config
from embeddings.embedder import create_embedder
from ingestion.indexer import Indexer
from json_io import load_rules_file
from llm.openrouter_client import OpenRouterClient
from models.schemas import SecurityRule
from retrieval.retriever import Retriever
from vector_store.chroma_store import ChromaStore

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    config = Config.from_env()
    if not config.openrouter_api_key:
        print("ERROR: OPENROUTER_API_KEY is not set.")
        return 1

    repo = ROOT / "benchmark" / "source"
    rules = [SecurityRule.from_dict(item) for item in load_rules_file(
        ROOT / "benchmark" / "security_rules.json")]

    print("=== Phase 1: index benchmark repository ===")
    embedder = create_embedder(config)
    print(f"embedder: {embedder.name} (dim={embedder.dim})")
    store = ChromaStore(persist_dir=str(ROOT / config.chroma_dir),
                        collection_name=config.collection_name)
    stats = Indexer(embedder, store).index_repository(repo)
    print(json.dumps(stats.to_dict(), indent=2))

    print("\n=== Phase 2: analyze rules via OpenRouter ===")
    llm = OpenRouterClient(config.openrouter_api_key, config.openrouter_model,
                           config.openrouter_base_url,
                           config.llm_timeout_seconds, config.llm_temperature)
    analyzer = SecurityAnalyzer(Retriever(embedder, store), llm,
                                EvidenceValidator(repo), top_k=config.top_k)
    start = time.time()
    report = analyzer.analyze(rules)

    for result in report.results:
        print(f"\nRule: {result.rule.rule_id} [{result.rule.severity}] "
              f"{result.rule.category}")
        print(f"  Retrieved: {len(result.retrieved)} code units")
        for r in result.retrieved:
            print(f"    - {r.unit.file}:{r.unit.start_line}-{r.unit.end_line} "
                  f"{r.unit.type} {r.unit.symbol} (score {r.score:.3f})")
        print(f"  LLM: {result.status} (confidence {result.confidence:.2f})")
        print(f"  Reason: {result.reason}")
        for e in result.evidence:
            print(f"  Evidence: {e.file}:{e.line} ({e.function}) "
                  f"[{'VALID' if e.valid else 'REJECTED: ' + e.validation_reason}]")
            print(f"    {e.code.strip()[:120]}")

    print("\n=== Metrics ===")
    print(json.dumps(report.metrics.to_dict(), indent=2))
    print(f"wall time: {time.time() - start:.1f}s")

    out = ROOT / "benchmark" / "last_live_report.json"
    out.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    print(f"\nreport written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
