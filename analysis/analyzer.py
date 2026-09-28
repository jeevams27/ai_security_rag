"""Per-rule security analysis orchestration.

For each rule (any number of rules; count comes entirely from input data):
    rule -> embedding -> Top-K retrieval -> LLM reasoning -> strict JSON
    -> evidence validation -> downgrade VULNERABLE without valid evidence
    -> deduplication.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from models.schemas import (
    ALLOWED_STATUSES,
    AnalysisMetrics,
    EvidenceItem,
    RuleResult,
    SecurityRule,
)
from retrieval.retriever import Retriever
from llm.prompts import SYSTEM_PROMPT, build_user_prompt, parse_llm_json
from .evidence_validator import EvidenceValidator
from .deduplicator import Finding, deduplicate_findings


@dataclass
class AnalysisReport:
    results: list[RuleResult] = field(default_factory=list)
    metrics: AnalysisMetrics = field(default_factory=AnalysisMetrics)

    def to_dict(self) -> dict:
        return {
            "results": [r.to_dict() for r in self.results],
            "metrics": self.metrics.to_dict(),
        }


class SecurityAnalyzer:
    def __init__(self, retriever: Retriever, llm_client,
                 validator: EvidenceValidator, top_k: int = 8) -> None:
        self.retriever = retriever
        self.llm = llm_client
        self.validator = validator
        self.top_k = top_k

    def analyze(self, rules: list[SecurityRule]) -> AnalysisReport:
        start = time.time()
        report = AnalysisReport()
        for rule in rules:  # arbitrary number of rules; no caps, no special cases
            result = self._analyze_rule(rule, report.metrics)
            report.results.append(result)
            report.metrics.rules_analyzed += 1
        report.metrics.runtime_seconds = time.time() - start
        return report

    def _analyze_rule(self, rule: SecurityRule, metrics: AnalysisMetrics) -> RuleResult:
        retrieved = self.retriever.retrieve(rule, top_k=self.top_k)
        metrics.retrievals += 1

        if not retrieved:
            return RuleResult(
                rule=rule, status="INCONCLUSIVE", confidence=0.0,
                reason="No relevant code units were retrieved for this rule.",
                retrieved=[],
            )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(rule, retrieved)},
        ]
        metrics.llm_calls += 1
        response = self.llm.chat(messages)
        metrics.prompt_tokens += response.prompt_tokens
        metrics.completion_tokens += response.completion_tokens
        metrics.total_tokens += response.total_tokens

        try:
            data = parse_llm_json(response.content)
        except ValueError as exc:
            return RuleResult(
                rule=rule, status="INCONCLUSIVE", confidence=0.0,
                reason=f"LLM response could not be parsed: {exc}",
                retrieved=retrieved, raw_response=response.content,
            )

        status = str(data.get("status", "INCONCLUSIVE")).upper()
        if status not in ALLOWED_STATUSES:
            status = "INCONCLUSIVE"
        try:
            confidence = max(0.0, min(1.0, float(data.get("confidence", 0.0))))
        except (TypeError, ValueError):
            confidence = 0.0
        reason = str(data.get("reason", ""))

        # Validate every evidence item against the real repository.
        validated: list[EvidenceItem] = [
            self.validator.validate(e)
            for e in data.get("evidence", []) or []
            if isinstance(e, dict)
        ]
        valid_evidence = [e for e in validated if e.valid]

        # Deduplicate identical findings (rule_id, file, function, line).
        unique_findings = deduplicate_findings([
            Finding(rule_id=rule.rule_id, file=e.file,
                    function=e.function, line=e.line)
            for e in valid_evidence
        ])
        first_keys = {(f.file, f.function, f.line) for f in unique_findings}
        deduped: list[EvidenceItem] = []
        seen_keys: set = set()
        for e in valid_evidence:
            key = (e.file, e.function, e.line)
            if key in first_keys and key not in seen_keys:
                seen_keys.add(key)
                deduped.append(e)

        # Never allow fabricated evidence to support a VULNERABLE verdict.
        if status == "VULNERABLE" and not deduped:
            status = "INCONCLUSIVE"
            reason += (" [downgraded: no evidence item could be verified "
                       "against the repository]")

        return RuleResult(
            rule=rule, status=status, confidence=confidence, reason=reason,
            evidence=deduped, retrieved=retrieved, raw_response=response.content,
        )
