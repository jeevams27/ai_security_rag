"""Streamlit explorer panels: inspect semantic chunks and Tree-sitter parse trees.

Used by app.py as extra tabs after indexing, so users can see exactly what
the pipeline extracted from their code before analysis runs.
"""

from __future__ import annotations

from pathlib import Path

import streamlit as st

from ingestion.file_discovery import discover_source_files
from ingestion.language_detector import detect_language
from ingestion.semantic_chunker import SemanticChunker
from ingestion.tree_sitter_parser import TreeSitterParser

# st.code() accepts these language names for syntax highlighting.
_HIGHLIGHT = {"python": "python", "java": "java", "javascript": "javascript",
              "typescript": "typescript", "tsx": "typescript", "c": "c",
              "cpp": "cpp", "go": "go"}

_TREE_BUDGET = 400  # max rendered tree lines; large files get truncated


def _pick_file(repo_dir: Path, key: str) -> tuple[Path, str] | None:
    """File picker shared by both panels. Returns (path, relative_posix)."""
    files = discover_source_files(repo_dir)
    if not files:
        st.info("No supported source files were indexed in this upload.")
        return None
    rels = [p.relative_to(repo_dir).as_posix() for p in files]
    rel = st.selectbox("Choose a file", rels, key=key)
    return repo_dir / rel, rel


def render_chunks_panel(repo_dir: Path) -> None:
    """Tab: table of semantic units + click-to-view full chunk code."""
    picked = _pick_file(repo_dir, key="chunk_file")
    if picked is None:
        return
    path, rel = picked
    language = detect_language(path)
    units = SemanticChunker().chunk_file(path, rel, language)

    st.caption(f"**{len(units)}** semantic unit(s) extracted from "
               f"`{rel}` (language: `{language}`)")
    st.dataframe(
        [{"symbol": u.symbol, "type": u.type, "lines": f"{u.start_line}-{u.end_line}",
          "chars": len(u.code), "id": u.id} for u in units],
        use_container_width=True)

    labels = [f"{u.symbol}  ({u.type}, lines {u.start_line}-{u.end_line})"
              for u in units]
    choice = st.selectbox("Inspect a chunk", labels, key="chunk_unit")
    unit = units[labels.index(choice)]
    st.caption("This exact text is what gets embedded and can be shown to "
               "the LLM during analysis.")
    st.code(unit.code, language=_HIGHLIGHT.get(unit.language))


def render_tree_panel(repo_dir: Path) -> None:
    """Tab: indented Tree-sitter parse tree for the selected file."""
    picked = _pick_file(repo_dir, key="tree_file")
    if picked is None:
        return
    path, rel = picked
    language = detect_language(path)
    source = path.read_bytes()
    tree = TreeSitterParser().parse(source, language)

    lines: list[str] = []

    def visit(node, depth: int) -> None:
        if len(lines) >= _TREE_BUDGET:
            return
        span = f"{node.start_point[0] + 1}-{node.end_point[0] + 1}"
        label = f"{'  ' * depth}{node.type}  [lines {span}]"
        if not node.children:  # leaf: show a short text preview
            text = source[node.start_byte:node.end_byte].decode(
                "utf-8", "replace").replace("\n", " ")[:40]
            label += f'  "{text}"'
        lines.append(label)
        for child in node.children:
            visit(child, depth + 1)

    visit(tree.root_node, 0)
    if len(lines) >= _TREE_BUDGET:
        lines.append(f"... [truncated at {_TREE_BUDGET} nodes]")

    st.caption(f"Tree-sitter parse tree for `{rel}` (grammar: `{language}`). "
               f"Nodes named `function_definition`, `class_declaration`, etc. "
               f"are what become chunks.")
    st.code("\n".join(lines), language="text")
