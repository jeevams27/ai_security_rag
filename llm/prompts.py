"""Prompt construction and strict-JSON response parsing for the LLM
security-reasoning layer."""

from __future__ import annotations

from typing import Any

from json_io import first_json_value
from models.schemas import RetrievedUnit, SecurityRule

SYSTEM_PROMPT = """You are a security-analysis reasoning engine.

You are given ONE security rule and a set of code units retrieved from a
repository because they appeared semantically relevant to the rule.

STRICT RULES:
- Analyze ONLY the supplied code. Do not invent source code.
- Do not invent files. Do not invent line numbers. Do not invent functions.
- Do not assume missing functions, missing validation, or missing authorization.
- Semantic similarity of the retrieved code to the rule is NOT proof of a
  vulnerability. You must reason about the actual code.
- If the retrieved context is insufficient to decide, return INCONCLUSIVE.
- Explain WHY the code satisfies or violates the rule.
- Every piece of evidence MUST be verifiable against the supplied code:
  copy the exact code snippet and use the exact file, line, and function
  from the supplied code-unit headers.

Respond with STRICT JSON ONLY (no markdown fences, no extra text):
{
  "status": "VULNERABLE" | "SAFE" | "INCONCLUSIVE",
  "confidence": <number between 0 and 1>,
  "reason": "<why the code satisfies or violates the rule>",
  "evidence": [
    {
      "file": "<exact file path from a code-unit header>",
      "line": <exact line number within that unit>,
      "function": "<exact symbol from a code-unit header>",
      "code": "<exact code snippet copied from the unit>",
      "reason": "<how this snippet relates to the rule>"
    }
  ]
}
Return an empty evidence list for SAFE or when nothing concrete can be cited.
"""


def build_user_prompt(rule: SecurityRule,
                      retrieved: list[RetrievedUnit]) -> str:
    parts = [
        "SECURITY RULE:",
        f"  id: {rule.rule_id}",
        f"  severity: {rule.severity}",
        f"  category: {rule.category}",
        f"  requirement: {rule.requirement}",
        "",
        "RETRIEVED CODE UNITS (candidate context, may contain false positives):",
    ]
    for i, item in enumerate(retrieved, 1):
        u = item.unit
        parts.append(
            f"\n--- UNIT {i} ---\n"
            f"file: {u.file}\n"
            f"language: {u.language}\n"
            f"{u.type}: {u.symbol}\n"
            f"lines: {u.start_line}-{u.end_line}\n"
            f"similarity: {item.score:.4f}\n"
            f"code:\n{u.code}"
        )
    parts.append(
        "\nDecide whether the rule is VIOLATED by the supplied code. "
        "Return strict JSON only."
    )
    return "\n".join(parts)


def parse_llm_json(text: str) -> dict[str, Any]:
    """Parse the LLM's strict-JSON response.

    Tolerates code fences, surrounding prose, and a SECOND JSON object (some
    models repeat the verdict or append a summary). Only the first complete
    JSON object is used; anything after it is ignored, so the response can no
    longer fail with "Extra data: line N column M (char K)".
    """
    try:
        data = first_json_value(text)
    except ValueError as exc:
        raise ValueError(
            f"LLM response is not JSON: {text[:200]!r} ({exc})") from exc
    if not isinstance(data, dict):
        raise ValueError("LLM response JSON is not an object")
    return data
