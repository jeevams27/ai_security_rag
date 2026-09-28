from models.schemas import CodeUnit, SecurityRule
from retrieval.retriever import Retriever


def _unit(symbol: str, code: str, file: str = "a.py") -> CodeUnit:
    return CodeUnit(file=file, language="python", symbol=symbol,
                    type="function", start_line=1,
                    end_line=code.count("\n") + 1, code=code)


def test_vector_insert_and_retrieve(embedder, store):
    units = [
        _unit("find_user", "query = 'SELECT * FROM users WHERE name = ' + name\n"
                           "cursor.execute(query)"),
        _unit("render_page", "template = load_template('home.html')\n"
                             "return render(template)"),
    ]
    store.add(units, embedder.embed_texts([u.embedding_text() for u in units]))
    assert store.count() == 2

    rule = SecurityRule(
        rule_id="SQL-001", severity="HIGH", category="SQL Injection",
        requirement="User-controlled input must not be concatenated directly "
                    "into SQL queries.")
    retriever = Retriever(embedder, store)
    results = retriever.retrieve(rule, top_k=2)
    assert len(results) == 2
    assert results[0].unit.symbol == "find_user"  # most similar first
    assert results[0].score >= results[1].score


def test_query_empty_store(embedder, store):
    assert store.query(embedder.embed_texts(["anything"])[0], top_k=5) == []
