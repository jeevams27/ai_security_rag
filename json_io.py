"""Tolerant JSON loading for user-supplied and LLM-supplied JSON.

Plain ``json.loads`` demands exactly ONE JSON value in the string. Every extra
byte after the first value raises::

    json.decoder.JSONDecodeError: Extra data: line 11 column 1 (char 336)

That happens in practice all the time:

* an LLM answers with the verdict object and then repeats or summarises it,
  so the text holds two objects;
* a rules file holds two arrays, or one rule object per line (JSONL);
* the rules box holds a single rule object instead of an array of rules;
* trailing prose, comments or a stray fence sits after the JSON.

The helpers below extract JSON values instead of insisting on exactly one, and
turn ``JSONDecodeError`` into a message that says what is wrong and where.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

# ```json / ``` openings and closing fences around otherwise valid JSON.
_OPEN_FENCE_RE = re.compile(r"^```[A-Za-z0-9_+-]*[ \t]*\r?\n?")
_CLOSE_FENCE_RE = re.compile(r"\r?\n?[ \t]*```[ \t]*$")


def _strip_fences(text: str) -> str:
    """Remove a single ```json ... ``` wrapper, if present."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = _OPEN_FENCE_RE.sub("", cleaned, count=1)
        cleaned = _CLOSE_FENCE_RE.sub("", cleaned, count=1)
    return cleaned.strip()


def _first_value_start(text: str) -> int:
    """Index of the first structured JSON value (`{` or `[`), else 0."""
    for index, char in enumerate(text):
        if char in "{[":
            return index
    return 0


def _describe(exc: json.JSONDecodeError, text: str) -> str:
    """Human-readable replacement for the bare json error message."""
    start = max(0, exc.pos - 30)
    near = text[start: exc.pos + 30].replace("\r", " ").replace("\n", "\\n")
    return (f"Invalid JSON at line {exc.lineno} column {exc.colno} "
            f"(character {exc.pos}): {exc.msg}. Nearby text: ...{near}...")


def first_json_value(text: str) -> Any:
    """Return the FIRST complete JSON value, ignoring anything after it.

    Tolerates code fences and leading prose. This is what makes a second
    object (or a trailing summary) harmless instead of an "Extra data" crash.
    """
    cleaned = _strip_fences(text)
    if not cleaned:
        raise ValueError("JSON input is empty.")
    try:
        value, _ = json.JSONDecoder().raw_decode(
            cleaned, _first_value_start(cleaned))
    except json.JSONDecodeError as exc:
        raise ValueError(_describe(exc, cleaned)) from exc
    return value


def all_json_values(text: str) -> list[Any]:
    """Return every complete top-level JSON value found in the text.

    Handles concatenated documents (`[...]` `[...]`) and JSONL
    (`{...}\\n{...}`). Trailing non-JSON text is ignored once at least one
    value has been read; if nothing could be read, the parse error is raised.
    """
    cleaned = _strip_fences(text)
    decoder = json.JSONDecoder()
    values: list[Any] = []
    index, length = _first_value_start(cleaned), len(cleaned)
    while index < length:
        while index < length and cleaned[index].isspace():
            index += 1
        if index >= length or cleaned[index] not in "{[":
            break  # trailing prose / not structured JSON
        try:
            value, index = decoder.raw_decode(cleaned, index)
        except json.JSONDecodeError as exc:
            if not values:
                raise ValueError(_describe(exc, cleaned)) from exc
            break  # malformed trailing fragment: keep what we already read
        values.append(value)
    return values


def loads_rules(text: str) -> list[dict[str, Any]]:
    """Load security rules from tolerant JSON text.

    Accepted shapes (all of them collapse to `list[dict]`):

    * one JSON array of rule objects;
    * a single rule object (wrapped into a one-item list);
    * several concatenated arrays (flattened in order);
    * one rule object per line, i.e. JSONL.
    """
    values = all_json_values(text)
    if not values:
        first_json_value(text)  # nothing parsed: raise the precise parse error
        raise ValueError("No security rules found in the JSON input.")

    rules: list[dict[str, Any]] = []
    for value in values:
        if isinstance(value, dict):
            rules.append(value)
        elif isinstance(value, list):
            for item in value:
                if not isinstance(item, dict):
                    raise ValueError(
                        "Each security rule must be a JSON object; found "
                        f"{type(item).__name__} inside the array.")
                rules.append(item)
        else:
            raise ValueError(
                "Security rules must be a JSON array of objects or a single "
                f"rule object; found {type(value).__name__}.")
    if not rules:
        raise ValueError("The security rules array is empty.")
    return rules


def load_rules_file(path: str | Path) -> list[dict[str, Any]]:
    """Read a rules file (UTF-8, BOM tolerated) and parse it tolerantly."""
    rules_path = Path(path)
    if not rules_path.is_file():
        raise ValueError(f"Rules file not found: {rules_path}")
    try:
        text = rules_path.read_text(encoding="utf-8-sig")
    except OSError as exc:
        raise ValueError(f"Could not read rules file {rules_path}: {exc}") from exc
    return loads_rules(text)


def load_rules_bytes(data: bytes) -> list[dict[str, Any]]:
    """Parse uploaded rules bytes (UTF-8, BOM tolerated)."""
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("The rules file is not valid UTF-8 text.") from exc
    return loads_rules(text)
