"""Repository file discovery. Language-agnostic; only filters by extension
and skips non-source directories / oversized or binary files."""

from __future__ import annotations

import os
from pathlib import Path

from .language_detector import EXTENSION_MAP

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", "target", ".idea", ".vscode", ".chroma",
    "out", "bin", "obj", ".mypy_cache", ".pytest_cache", ".tox",
}

DEFAULT_MAX_FILE_BYTES = 1_000_000


def discover_source_files(
    root: str | os.PathLike, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
) -> list[Path]:
    """Return all supported source files under `root`, sorted for determinism."""
    root_path = Path(root)
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in EXTENSION_MAP:
                continue
            try:
                if path.stat().st_size > max_file_bytes:
                    continue
                with open(path, "rb") as fh:
                    if b"\x00" in fh.read(2048):  # binary guard
                        continue
            except OSError:
                continue
            files.append(path)
    return sorted(files)


def discover_unsupported_files(root: str | os.PathLike) -> list[Path]:
    """Files under `root` that are skipped because their extension is not in
    EXTENSION_MAP. Used to surface skipped uploads instead of hiding them."""
    root_path = Path(root)
    skipped: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in EXTENSION_MAP:
                skipped.append(path)
    return sorted(skipped)
