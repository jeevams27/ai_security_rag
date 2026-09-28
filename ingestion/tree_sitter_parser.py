"""Tree-sitter parsing layer with a language-adapter registry.

Each supported language is described by a `LanguageSpec`:
  - how to load its Tree-sitter grammar
  - which node types are semantic code units (functions / methods / classes)

To add a language later: add an entry to LANGUAGE_SPECS (+ extension map).
The rest of the security-analysis pipeline does not change.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass, field

from tree_sitter import Language, Parser, Node, Tree


@dataclass(frozen=True)
class LanguageSpec:
    name: str
    module: str  # python module providing the grammar
    language_attr: str = "language"  # attribute returning the PyCapsule
    function_nodes: tuple[str, ...] = ()  # executable semantic units
    class_nodes: tuple[str, ...] = ()  # type/container semantic units
    type_labels: dict[str, str] = field(default_factory=dict)


LANGUAGE_SPECS: dict[str, LanguageSpec] = {
    "python": LanguageSpec(
        name="python", module="tree_sitter_python",
        function_nodes=("function_definition",),
        class_nodes=("class_definition",),
    ),
    "java": LanguageSpec(
        name="java", module="tree_sitter_java",
        function_nodes=("method_declaration", "constructor_declaration"),
        class_nodes=("class_declaration", "interface_declaration"),
        type_labels={"constructor_declaration": "constructor",
                     "method_declaration": "method",
                     "interface_declaration": "interface"},
    ),
    "javascript": LanguageSpec(
        name="javascript", module="tree_sitter_javascript",
        function_nodes=("function_declaration", "method_definition",
                        "generator_function_declaration"),
        class_nodes=("class_declaration",),
        type_labels={"method_definition": "method"},
    ),
    "typescript": LanguageSpec(
        name="typescript", module="tree_sitter_typescript",
        language_attr="language_typescript",
        function_nodes=("function_declaration", "method_definition",
                        "generator_function_declaration"),
        class_nodes=("class_declaration", "interface_declaration"),
        type_labels={"method_definition": "method",
                     "interface_declaration": "interface"},
    ),

    "tsx": LanguageSpec(
        name="tsx", module="tree_sitter_typescript",
        language_attr="language_tsx",
        function_nodes=("function_declaration", "method_definition",
                        "generator_function_declaration"),
        class_nodes=("class_declaration", "interface_declaration"),
        type_labels={"method_definition": "method",
                     "interface_declaration": "interface"},
    ),
    "c": LanguageSpec(
        name="c", module="tree_sitter_c",
        function_nodes=("function_definition",),
        class_nodes=("struct_specifier",),
        type_labels={"struct_specifier": "struct"},
    ),
    "cpp": LanguageSpec(
        name="cpp", module="tree_sitter_cpp",
        function_nodes=("function_definition",),
        class_nodes=("class_specifier", "struct_specifier"),
        type_labels={"class_specifier": "class", "struct_specifier": "struct"},
    ),
    "go": LanguageSpec(
        name="go", module="tree_sitter_go",
        function_nodes=("function_declaration", "method_declaration"),
        class_nodes=("type_declaration",),
        type_labels={"method_declaration": "method",
                     "type_declaration": "type"},
    ),
}


class TreeSitterParser:
    """Loads grammars lazily and parses source bytes into syntax trees."""

    def __init__(self) -> None:
        self._languages: dict[str, Language] = {}
        self._parsers: dict[str, Parser] = {}

    def supported_languages(self) -> list[str]:
        return sorted(LANGUAGE_SPECS)

    def _load_language(self, name: str) -> Language:
        if name in self._languages:
            return self._languages[name]
        spec = LANGUAGE_SPECS.get(name)
        if spec is None:
            raise ValueError(f"No Tree-sitter language adapter registered for '{name}'")
        try:
            module = importlib.import_module(spec.module)
        except ImportError as exc:
            raise ValueError(
                f"Grammar package '{spec.module}' for language '{name}' is not "
                f"installed. Install it to enable '{name}' support."
            ) from exc
        capsule = getattr(module, spec.language_attr)
        language = Language(capsule() if callable(capsule) else capsule)
        self._languages[name] = language
        return language

    def get_parser(self, language: str) -> Parser:
        if language not in self._parsers:
            self._parsers[language] = Parser(self._load_language(language))
        return self._parsers[language]

    def parse(self, source: bytes, language: str) -> Tree:
        return self.get_parser(language).parse(source)


def node_name(node: Node, source: bytes) -> str:
    """Best-effort symbol-name extraction, language-agnostic with fallbacks."""
    name_node = node.child_by_field_name("name")
    if name_node is not None:
        return source[name_node.start_byte:name_node.end_byte].decode("utf-8", "replace")
    # C/C++: function_definition -> declarator chain -> ... -> identifier
    decl = node.child_by_field_name("declarator")
    while decl is not None:
        inner = decl.child_by_field_name("declarator")
        if inner is None:
            if decl.type in ("identifier", "field_identifier"):
                return source[decl.start_byte:decl.end_byte].decode("utf-8", "replace")
            break
        decl = inner
    # Go type_declaration: look for type_spec name
    for child in node.children:
        if child.type == "type_spec":
            nn = child.child_by_field_name("name")
            if nn is not None:
                return source[nn.start_byte:nn.end_byte].decode("utf-8", "replace")
    return "<anonymous>"
