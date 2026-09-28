from ingestion.language_detector import detect_language
from ingestion.file_discovery import discover_source_files
from ingestion.tree_sitter_parser import TreeSitterParser


def test_language_detection():
    assert detect_language("a/b.py") == "python"
    assert detect_language("A.java") == "java"
    assert detect_language("x/Component.tsx") == "tsx"
    assert detect_language("x/app.ts") == "typescript"
    assert detect_language("main.c") == "c"
    assert detect_language("main.cpp") == "cpp"
    assert detect_language("main.go") == "go"
    assert detect_language("README.md") is None
    assert detect_language("noextension") is None


def test_file_discovery_skips_non_source(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("def a():\n    pass\n")
    (tmp_path / "src" / "b.txt").write_text("not source")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "c.py").write_text("def c():\n    pass\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "d.js").write_text("function d() {}")
    found = [p.name for p in discover_source_files(tmp_path)]
    assert found == ["a.py"]


def test_parser_all_languages_load():
    parser = TreeSitterParser()
    samples = {
        "python": b"def f():\n    pass\n",
        "java": b"class A { void m() {} }\n",
        "javascript": b"function f() {}\n",
        "typescript": b"function f(): void {}\n",
        "c": b"int f(void) { return 0; }\n",
        "cpp": b"int f() { return 0; }\n",
        "go": b"package main\nfunc f() {}\n",
    }
    for language, source in samples.items():
        tree = parser.parse(source, language)
        assert tree.root_node is not None
        assert not tree.root_node.has_error, f"parse error for {language}"
