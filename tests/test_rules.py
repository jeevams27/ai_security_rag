import json
from pathlib import Path

import pytest

from models.schemas import SecurityRule

BENCH_RULES = Path(__file__).parent.parent / "benchmark" / "security_rules.json"


def test_load_benchmark_rules():
    raw = json.loads(BENCH_RULES.read_text(encoding="utf-8"))
    rules = [SecurityRule.from_dict(item) for item in raw]
    assert len(rules) == 3
    assert all(r.rule_id and r.requirement for r in rules)


def test_missing_field_rejected():
    with pytest.raises(ValueError):
        SecurityRule.from_dict({"rule_id": "X-1", "severity": "LOW"})


def test_arbitrary_rule_counts():
    # Rule count comes entirely from input data: 1, 5, 50, 100 rules must all work.
    for n in (1, 5, 50, 100):
        rules = [
            SecurityRule.from_dict({
                "rule_id": f"R-{i}", "severity": "LOW",
                "category": f"cat-{i}", "requirement": f"requirement {i}"})
            for i in range(n)
        ]
        assert len(rules) == n
        assert len({r.render() for r in rules}) == n
