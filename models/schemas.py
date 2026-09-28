"""Core data structures shared across the whole pipeline.

Everything downstream of Tree-sitter treats every language identically:
the only contract is the `CodeUnit` shape below.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


def _unit_id(file: str, symbol: str, start_line: int, end_line: int) -> str:
    raw = f"{file}|{symbol}|{start_line}|{end_line}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class CodeUnit:
    """A semantic unit of code (function / method / class / module)."""

    file: str
    language: str
    symbol: str
    type: str  # function | method | class | interface | constructor | module
    start_line: int  # 1-based, inclusive
    end_line: int  # 1-based, inclusive
    code: str
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = _unit_id(self.file, self.symbol, self.start_line, self.end_line)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "language": self.language,
            "symbol": self.symbol,
            "type": self.type,
            "start_line": self.start_line,
            "end_line": self.end_line,
        }

    def embedding_text(self) -> str:
        """Text embedded for this unit: metadata header + code."""
        return (
            f"file: {self.file}\nlanguage: {self.language}\n"
            f"{self.type}: {self.symbol}\n{self.code}"
        )


@dataclass
class SecurityRule:
    """A structured security rule supplied as INPUT DATA.

    Rules are never hard-coded; any number of rules can be provided.
    """

    rule_id: str
    severity: str
    category: str
    requirement: str
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityRule":
        known = {"rule_id", "severity", "category", "requirement"}
        missing = known - set(data)
        if missing:
            raise ValueError(f"Security rule is missing fields: {sorted(missing)}")
        return cls(
            rule_id=str(data["rule_id"]),
            severity=str(data["severity"]),
            category=str(data["category"]),
            requirement=str(data["requirement"]),
            extra={k: v for k, v in data.items() if k not in known},
        )

    def render(self) -> str:
        """Text representation embedded for semantic retrieval."""
        return (
            f"Security category: {self.category}\n"
            f"Severity: {self.severity}\n"
            f"Requirement: {self.requirement}"
        )


@dataclass
class RetrievedUnit:
    unit: CodeUnit
    score: float  # similarity score, higher = more similar


@dataclass
class EvidenceItem:
    file: str
    line: int
    function: str
    code: str
    reason: str
    valid: bool = False
    validation_reason: str = ""


ALLOWED_STATUSES = {"VULNERABLE", "SAFE", "INCONCLUSIVE"}


@dataclass
class RuleResult:
    rule: SecurityRule
    status: str
    confidence: float
    reason: str
    evidence: list[EvidenceItem] = field(default_factory=list)
    retrieved: list[RetrievedUnit] = field(default_factory=list)
    raw_response: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "severity": self.rule.severity,
            "category": self.rule.category,
            "status": self.status,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence": [asdict(e) for e in self.evidence],
            "retrieved": [
                {"score": r.score, **r.unit.to_metadata()} for r in self.retrieved
            ],
        }


@dataclass
class AnalysisMetrics:
    files_indexed: int = 0
    lines_indexed: int = 0
    code_units_indexed: int = 0
    rules_analyzed: int = 0
    retrievals: int = 0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    runtime_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
