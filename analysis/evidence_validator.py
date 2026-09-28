"""Evidence validation: never blindly trust the LLM.

For every evidence item the LLM cites, verify against the real repository:
the file must exist, the line must be in range, the quoted code must
actually appear there, and the named function should match.
"""

from __future__ import annotations

from pathlib import Path

from models.schemas import EvidenceItem


class EvidenceValidator:
    def __init__(self, repo_dir) -> None:
        self.repo_dir = Path(repo_dir)
        self.files: list[Path] = [
            p for p in self.repo_dir.rglob("*") if p.is_file()
        ]

    # -- file resolution -------------------------------------------------
    def _resolve_file(self, cited: str) -> Path | None:
        cited = cited.strip().lstrip("./").replace("\\", "/")
        if not cited:
            return None
        # 1. exact path relative to repo root
        exact = self.repo_dir / cited
        if exact.is_file():
            return exact
        # 2. path suffix match (LLM cited a shorter/longer prefix)
        for p in self.files:
            rel = p.relative_to(self.repo_dir).as_posix()
            if rel.endswith(cited) or cited.endswith(rel):
                return p
        # 3. basename match (e.g. LLM said "UserService.java" for a
        #    pasted snippet stored under a nested name)
        base = Path(cited).name
        for p in self.files:
            if p.name == base:
                return p
        return None

    # -- content checks ----------------------------------------------------
    @staticmethod
    def _norm(text: str) -> str:
        return "".join(text.split())

    def validate(self, evidence: dict) -> EvidenceItem:
        item = EvidenceItem(
            file=str(evidence.get("file", "")),
            line=int(evidence.get("line", 0) or 0),
            function=str(evidence.get("function", "")),
            code=str(evidence.get("code", "")),
            reason=str(evidence.get("reason", "")),
        )

        path = self._resolve_file(item.file)
        if path is None:
            item.validation_reason = f"file '{item.file}' not found in repository"
            return item

        # Normalize the file to the repo-relative path so downstream
        # rendering shows the real file name.
        item.file = path.relative_to(self.repo_dir).as_posix()
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            item.validation_reason = f"could not read file: {exc}"
            return item

        if item.line < 1 or item.line > len(lines):
            item.validation_reason = (f"line {item.line} out of range "
                                      f"(file has {len(lines)} lines)")
            return item

        # The quoted code must actually appear near the cited line
        # (search a small window to tolerate off-by-a-few line numbers).
        window = 5
        lo = max(0, item.line - 1 - window)
        hi = min(len(lines), item.line - 1 + window + 1)
        nearby = self._norm("\n".join(lines[lo:hi]))
        cited_code = self._norm(item.code)
        if cited_code and cited_code not in nearby and cited_code not in self._norm("\n".join(lines)):
            item.validation_reason = "quoted code does not appear in the file"
            return item

        # If a function name is cited, it should exist somewhere in the file.
        if item.function and item.function not in "\n".join(lines):
            item.validation_reason = (f"function '{item.function}' not found "
                                      f"in '{item.file}'")
            return item

        item.valid = True
        item.validation_reason = "verified against repository"
        return item
