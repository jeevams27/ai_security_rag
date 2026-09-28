"""Deduplication of findings.

The same vulnerability can surface through multiple retrieved code units.
A finding is identified by (rule_id, file, function/symbol, line).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    file: str
    function: str
    line: int

    @property
    def key(self) -> tuple[str, str, str, int]:
        return (self.rule_id, self.file, self.function, self.line)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str, int]] = set()
    unique: list[Finding] = []
    for finding in findings:
        if finding.key in seen:
            continue
        seen.add(finding.key)
        unique.append(finding)
    return unique
