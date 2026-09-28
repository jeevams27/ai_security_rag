"""Extracts semantic code units from Tree-sitter syntax trees.

NOT arbitrary fixed-size line chunks: each unit is a real syntactic
construct (function / method / class / interface / ...). If a file has no
such constructs, the whole file becomes a single `module` unit so it can
still be retrieved.
"""

from __future__ import annotations

from pathlib import Path

from tree_sitter import Node

from models.schemas import CodeUnit
from .tree_sitter_parser import TreeSitterParser, LANGUAGE_SPECS, node_name


class SemanticChunker:
    def __init__(self, parser: TreeSitterParser | None = None,
                 max_unit_chars: int = 6000) -> None:
        self.parser = parser or TreeSitterParser()
        self.max_unit_chars = max_unit_chars

    def chunk_file(self, path: str | Path, rel_path: str, language: str) -> list[CodeUnit]:
        source = Path(path).read_bytes()
        return self.chunk_source(source, rel_path, language)

    def chunk_source(self, source: bytes, rel_path: str, language: str) -> list[CodeUnit]:
        tree = self.parser.parse(source, language)
        spec = LANGUAGE_SPECS[language]
        wanted = set(spec.function_nodes) | set(spec.class_nodes)
        units: list[CodeUnit] = []

        def visit(node: Node) -> None:
            # Python decorators wrap definitions; unwrap to the real definition.
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type in wanted:
                        self._add_unit(child, node, source, rel_path, language, spec, units)
                        # still recurse for nested definitions inside
                        for sub in child.children:
                            visit(sub)
                        return
            if node.type in wanted:
                self._add_unit(node, node, source, rel_path, language, spec, units)
            for child in node.children:
                visit(child)

        visit(tree.root_node)
        if not units:
            code = source.decode("utf-8", "replace")
            lines = code.count("\n") + 1
            units.append(CodeUnit(
                file=rel_path, language=language, symbol=Path(rel_path).name,
                type="module", start_line=1, end_line=lines,
                code=self._cap(code),
            ))
        return units

    def _add_unit(self, node: Node, extent_node: Node, source: bytes,
                  rel_path: str, language: str, spec, units: list[CodeUnit]) -> None:
        code = source[extent_node.start_byte:extent_node.end_byte].decode("utf-8", "replace")
        type_label = spec.type_labels.get(node.type)
        if type_label is None:
            type_label = "class" if node.type in spec.class_nodes else "function"
        units.append(CodeUnit(
            file=rel_path,
            language=language,
            symbol=node_name(node, source),
            type=type_label,
            start_line=extent_node.start_point[0] + 1,
            end_line=extent_node.end_point[0] + 1,
            code=self._cap(code),
        ))

    def _cap(self, code: str) -> str:
        if len(code) <= self.max_unit_chars:
            return code
        return code[: self.max_unit_chars] + "\n# ... [truncated]"
