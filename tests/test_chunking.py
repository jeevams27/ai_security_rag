from ingestion.semantic_chunker import SemanticChunker

PY = (
    b"def update_user(uid, name):\n"
    b"    return save(uid, name)\n"
    b"\n"
    b"class UserService:\n"
    b"    def get(self, uid):\n"
    b"        return load(uid)\n"
)

JAVA = (
    b"public class UserService {\n"
    b"  public void updateUser(int id) {\n"
    b"    db.save(id);\n"
    b"  }\n"
    b"}\n"
)

JS = b"function updateUser(id) {\n  return db.query(id);\n}\n"


def test_python_functions_and_classes():
    units = SemanticChunker().chunk_source(PY, "svc/user.py", "python")
    by_symbol = {u.symbol: u for u in units}
    assert "update_user" in by_symbol
    assert "UserService" in by_symbol
    assert "get" in by_symbol
    fn = by_symbol["update_user"]
    assert fn.type == "function"
    assert fn.start_line == 1 and fn.end_line == 2
    assert "def update_user" in fn.code
    assert by_symbol["UserService"].type == "class"


def test_java_methods():
    units = SemanticChunker().chunk_source(JAVA, "UserService.java", "java")
    by_symbol = {u.symbol: u for u in units}
    assert by_symbol["updateUser"].type == "method"
    assert by_symbol["UserService"].type == "class"


def test_javascript_function():
    units = SemanticChunker().chunk_source(JS, "user.js", "javascript")
    assert units[0].symbol == "updateUser"
    assert units[0].type == "function"


def test_units_have_required_metadata():
    units = SemanticChunker().chunk_source(PY, "svc/user.py", "python")
    for u in units:
        assert u.id and u.file == "svc/user.py" and u.language == "python"
        assert u.start_line >= 1 and u.end_line >= u.start_line
        assert u.code.strip()


def test_module_fallback_for_unitless_file():
    units = SemanticChunker().chunk_source(b"x = 1\ny = 2\n", "cfg.py", "python")
    assert len(units) == 1
    assert units[0].type == "module"
