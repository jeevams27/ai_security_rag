"""Tests for tolerant JSON loading (json_io).

Regression focus: `json.loads` raised

    JSONDecodeError: Extra data: line 11 column 1 (char 336)

whenever the text held a valid JSON value followed by anything else -- an LLM
repeating its verdict object, a rules file with two arrays, or JSONL rules.
These tests pin the tolerant behaviour that replaces that crash.
"""

import json

import pytest

from json_io import (
    all_json_values,
    first_json_value,
    load_rules_bytes,
    load_rules_file,
    loads_rules,
)
from llm.prompts import parse_llm_json

RULE_A = {"rule_id": "SQL-001", "severity": "HIGH",
          "category": "SQL Injection", "requirement": "no concatenation"}
RULE_B = {"rule_id": "CMD-001", "severity": "CRITICAL",
          "category": "Command Injection", "requirement": "no shell=True"}


# -- first_json_value ---------------------------------------------------
def test_first_value_ignores_second_object_the_extra_data_bug():
    # The exact shape that produced "Extra data: line N column 1 (char M)".
    text = json.dumps({"status": "VULNERABLE", "confidence": 0.9}) + "\n" + \
        json.dumps({"status": "SAFE"})
    assert first_json_value(text)["status"] == "VULNERABLE"


def test_first_value_ignores_trailing_prose_and_leading_prose():
    assert first_json_value('Here is the result:\n{"status": "SAFE"}\n'
                            'Let me know if you need more.')["status"] == "SAFE"


def test_first_value_strips_code_fences():
    text = '```json\n{"status": "SAFE", "confidence": 0.5}\n```'
    assert first_json_value(text)["confidence"] == 0.5


def test_first_value_reports_position_when_truncated():
    with pytest.raises(ValueError) as exc:
        first_json_value('{"status": "VULNERABLE", "evidence": [')
    assert "Invalid JSON at line 1 column" in str(exc.value)


def test_first_value_rejects_empty_input():
    with pytest.raises(ValueError):
        first_json_value("   ")


# -- all_json_values ----------------------------------------------------
def test_all_values_reads_concatenated_arrays():
    text = json.dumps([RULE_A]) + "\n" + json.dumps([RULE_B])
    values = all_json_values(text)
    assert len(values) == 2


def test_all_values_reads_jsonl():
    text = json.dumps(RULE_A) + "\n" + json.dumps(RULE_B) + "\n"
    assert len(all_json_values(text)) == 2


def test_all_values_stops_at_trailing_prose():
    text = json.dumps([RULE_A]) + "\nThanks!"
    assert all_json_values(text) == [[RULE_A]]


# -- loads_rules --------------------------------------------------------
def test_loads_rules_accepts_an_array():
    assert loads_rules(json.dumps([RULE_A, RULE_B])) == [RULE_A, RULE_B]


def test_loads_rules_wraps_a_single_object():
    assert loads_rules(json.dumps(RULE_A)) == [RULE_A]


def test_loads_rules_flattens_concatenated_arrays():
    text = json.dumps([RULE_A]) + "\n" + json.dumps([RULE_B])
    assert loads_rules(text) == [RULE_A, RULE_B]


def test_loads_rules_merges_jsonl_and_prose():
    text = "rules below:\n" + json.dumps(RULE_A) + "\n" + json.dumps(RULE_B)
    assert loads_rules(text) == [RULE_A, RULE_B]


def test_loads_rules_rejects_non_object_items():
    with pytest.raises(ValueError, match="must be a JSON object"):
        loads_rules(json.dumps([RULE_A, "just a string"]))


def test_loads_rules_rejects_empty_array():
    with pytest.raises(ValueError, match="empty"):
        loads_rules("[]")


def test_loads_rules_reports_clear_error_for_garbage():
    with pytest.raises(ValueError, match="Invalid JSON"):
        loads_rules("this is not json")


# -- file / bytes loaders ----------------------------------------------
def test_load_rules_file_reads_utf8_with_bom(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps([RULE_A]), encoding="utf-8-sig")
    assert load_rules_file(path) == [RULE_A]


def test_load_rules_file_missing_path_is_clear(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        load_rules_file(tmp_path / "nope.json")


def test_load_rules_bytes_rejects_non_utf8():
    with pytest.raises(ValueError, match="not valid UTF-8"):
        load_rules_bytes(b"\xff\xfe\x00[")


# -- LLM response path --------------------------------------------------
def test_parse_llm_json_uses_first_object_when_model_repeats_itself():
    text = (json.dumps({"status": "VULNERABLE", "confidence": 0.8,
                        "reason": "bad", "evidence": []})
            + "\n"
            + json.dumps({"status": "SAFE", "confidence": 0.1}))
    assert parse_llm_json(text)["status"] == "VULNERABLE"


def test_parse_llm_json_still_rejects_non_json():
    with pytest.raises(ValueError, match="not JSON"):
        parse_llm_json("not json at all")


def test_parse_llm_json_rejects_non_object():
    with pytest.raises(ValueError, match="not an object"):
        parse_llm_json("[1, 2, 3]")
