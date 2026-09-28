"""Offline end-to-end test: index -> retrieve -> (mocked) LLM -> validate
evidence -> dedupe. No API calls."""

import json
from pathlib import Path

from analysis.evidence_validator import EvidenceValidator
from analysis.analyzer import SecurityAnalyzer
from analysis.deduplicator import Finding, deduplicate_findings
from ingestion.indexer import Indexer
from llm.prompts import parse_llm_json
from models.schemas import SecurityRule
from retrieval.retriever import Retriever
from tests.conftest import FakeLLM


def _write_repo(root: Path) -> None:
    (root / "vulnerable.py").write_text(
        "import sqlite3\n"
        "\n"
        "def find_user(username):\n"
        "    query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
        "    cursor.execute(query)\n"
    )
    (root / "safe.py").write_text(
        "def render_home():\n"
        "    return render_template('home.html')\n"
    )


def _index(embedder, store, repo):
    return Indexer(embedder, store).index_repository(repo)


def test_indexing_stats_and_cache(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    stats = _index(embedder, store, repo)
    assert stats.files == 2
    assert stats.code_units == 2  # find_user + render_home
    assert stats.embeddings == 2

    # Second run: unchanged files must be reused from cache, not re-embedded.
    stats2 = _index(embedder, store, repo)
    assert stats2.files_reused_from_cache == 2
    assert stats2.embeddings == 0
    assert store.count() == 2


def test_end_to_end_vulnerable_with_valid_evidence(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    _index(embedder, store, repo)

    llm_json = json.dumps({
        "status": "VULNERABLE", "confidence": 0.95,
        "reason": "User input is concatenated into SQL.",
        "evidence": [
            {"file": "vulnerable.py", "line": 4, "function": "find_user",
             "code": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"",
             "reason": "direct concatenation"},
            # duplicate of the same finding -> must be deduplicated
            {"file": "vulnerable.py", "line": 4, "function": "find_user",
             "code": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"",
             "reason": "direct concatenation"},
        ],
    })
    llm = FakeLLM([llm_json])
    analyzer = SecurityAnalyzer(Retriever(embedder, store), llm,
                                EvidenceValidator(repo), top_k=2)
    rules = [SecurityRule.from_dict({
        "rule_id": "SQL-001", "severity": "HIGH", "category": "SQL Injection",
        "requirement": "User-controlled input must not be concatenated "
                       "directly into SQL queries."})]
    report = analyzer.analyze(rules)
    result = report.results[0]

    assert result.status == "VULNERABLE"
    assert result.confidence == 0.95
    assert len(result.evidence) == 1  # duplicate removed
    assert result.evidence[0].valid
    assert result.retrieved  # retrieval produced candidates
    m = report.metrics
    assert m.rules_analyzed == 1 and m.llm_calls == 1
    assert m.prompt_tokens == 10 and m.total_tokens == 15


def test_vulnerable_without_valid_evidence_downgraded(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    _index(embedder, store, repo)

    llm_json = json.dumps({
        "status": "VULNERABLE", "confidence": 0.9,
        "reason": "fabricated claim",
        "evidence": [
            {"file": "ghost.py", "line": 42, "function": "nope",
             "code": "system('rm -rf /')", "reason": "invented"},
        ],
    })
    llm = FakeLLM([llm_json])
    analyzer = SecurityAnalyzer(Retriever(embedder, store), llm,
                                EvidenceValidator(repo), top_k=2)
    rules = [SecurityRule.from_dict({
        "rule_id": "CMD-001", "severity": "CRITICAL",
        "category": "Command Injection",
        "requirement": "User-controlled input must not be passed into "
                       "operating-system command execution."})]
    result = analyzer.analyze(rules).results[0]
    assert result.status == "INCONCLUSIVE"
    assert "downgraded" in result.reason
    assert result.evidence == []


def test_malformed_llm_json_is_inconclusive(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _write_repo(repo)
    _index(embedder, store, repo)
    llm = FakeLLM(["not json at all"])
    analyzer = SecurityAnalyzer(Retriever(embedder, store), llm,
                                EvidenceValidator(repo), top_k=2)
    rule = SecurityRule.from_dict({
        "rule_id": "X", "severity": "LOW", "category": "c",
        "requirement": "r"})
    result = analyzer.analyze([rule]).results[0]
    assert result.status == "INCONCLUSIVE"
    assert "could not be parsed" in result.reason


def test_parse_llm_json_tolerates_fences():
    data = parse_llm_json("```json\n{\"status\": \"SAFE\", \"confidence\": 0.5, "
                          "\"reason\": \"ok\", \"evidence\": []}\n```")
    assert data["status"] == "SAFE"


def test_deduplicate_findings():
    findings = [
        Finding("SQL-001", "a.py", "f", 10),
        Finding("SQL-001", "a.py", "f", 10),
        Finding("SQL-001", "a.py", "f", 11),
        Finding("SQL-001", "b.py", "f", 10),
        Finding("PATH-001", "a.py", "f", 10),
    ]
    assert len(deduplicate_findings(findings)) == 4
