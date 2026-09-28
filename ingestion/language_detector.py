"""File-extension based language detection.

Adding a new language = adding its extension(s) here plus a Tree-sitter
adapter entry in tree_sitter_parser.LANGUAGE_SPECS. Nothing else changes.
"""

from __future__ import annotations

import os
from typing import Optional

EXTENSION_MAP: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".go": "go",
}

SUPPORTED_LANGUAGES = sorted(set(EXTENSION_MAP.values()))


def detect_language(path: str | os.PathLike) -> Optional[str]:
    name = str(path)
    if "." not in name:
        return None
    return EXTENSION_MAP.get("." + name.rsplit(".", 1)[-1].lower())
