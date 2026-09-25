# AI Security RAG Analyzer

A language-agnostic, retrieval-augmented security analyzer. Given a source
repository and any number of structured security rules, it finds the code
relevant to each rule and uses an LLM to decide whether that code violates
the rule — with every cited line of evidence verified against the real
repository.

## Architecture

One pipeline, two phases. Index once per repository, then analyze any number of security rules:

```text
                    .- PHASE 1: INDEX (once) ----------------.
                    | repo files -> parse -> embed -> Chroma |
                    `---------------------+------------------'
                                          |
                                          v
User --> app.py (Streamlit) --> .- PHASE 2: ANALYZE (per rule) -------------.
   ^                            | rule -> retrieve Top-K -> LLM -> validate |
   |                            `---------------------+----------------------'
   `---------------- findings + JSON report ---------'
```

Responsibilities are strictly separated:

| Component | Question it answers |
|---|---|
| Tree-sitter | What are the meaningful pieces of code? |
| Vector search | Which pieces appear relevant to this security requirement? |
| LLM | Does the retrieved code actually violate the requirement? |
| Evidence validator | Did the LLM evidence actually exist in the repository? |

### Phase 1 - Index (Build Index button -> app.py -> ingestion/)

```text
repo_dir --> index_repository() --> load manifest (cache) + discover files
                                                        |
                        per file: detect language --> hash content
                                                        |
                          .---------------+------------.
                          v                            v
                     unchanged                    changed / new
                  reuse old units         SemanticChunker -> Tree-sitter ->
                                          CodeUnits -> Embeddings -> ChromaDB
                          `---------------+------------'
                                          v
              remove deleted files --> save manifest --> IndexStats
```

The content-hash manifest is what makes re-indexing incremental:
unchanged files skip parsing, embedding and ChromaDB writes entirely.

### Phase 2 - Analyze (Analyze Security button -> analysis/ + llm/)

```text
per rule: embed requirement --> Top-K retrieval from ChromaDB
                                                        |
                                                        v
                         LLM judges candidates (strict JSON verdict)
                                                        |
                                                        v
                    validate evidence on disk --> drop unverified --> dedupe
                                                        |
                                                        v
                             report: VULNERABLE-only findings
                      (why + file/line/function/code + fix guidance)
```

Vector search is candidate generation, not proof: the LLM makes the
security judgment, and only evidence verified against the real repository
reaches the report.

## Why not send the whole repository to the LLM?

A 100K-line repository does not fit (economically or technically) into a
prompt, and most of it is irrelevant to any given rule. Instead the
repository is parsed and embedded **once**; each rule retrieves only the
Top-K relevant semantic units (default 8), so LLM input scales with the
retrieved context, not with repository size.

## Why Tree-sitter?

Tree-sitter provides fast, incremental, grammar-based parsing for many
languages. Instead of splitting code into arbitrary fixed-size line chunks,
the indexer extracts real syntactic constructs (`function_definition`,
`method_declaration`, `class_declaration`, ...). Each language has a small
adapter entry; adding a language never changes the analysis pipeline.

## Why embeddings + vector search?

Security requirements are natural language ("user-controlled input must not
be concatenated into SQL queries"). Embeddings map both requirements and
code into the same vector space, so semantically relevant code is found
without hard-coded, per-rule keyword logic. Vector search is **candidate
generation, not proof** — the LLM makes the security judgment.

## Security rule format

Rules are structured JSON **input data**. Nothing is keyed on rule IDs, and
1, 5, 20, 50 or 100 rules work with zero code changes:

```json
[
  {
    "rule_id": "SQL-001",
    "severity": "HIGH",
    "category": "SQL Injection",
    "requirement": "User-controlled input must not be concatenated directly into SQL queries."
  }
]
```

## Supported languages

Python, Java, JavaScript, TypeScript/TSX, C, C++, Go — via Tree-sitter
grammars. To add a language: add its extension to
`ingestion/language_detector.py` and an adapter to
`ingestion/tree_sitter_parser.py` (`LANGUAGE_SPECS`).

ps, consider
   batching/async LLM calls and a cross-encoder reranker.
