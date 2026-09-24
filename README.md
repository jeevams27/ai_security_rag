# AI Security RAG Analyzer

A language-agnostic, retrieval-augmented security analyzer. Given a source
repository and any number of structured security rules, it finds the code
relevant to each rule and uses an LLM to decide whether that code violates
the rule — with every cited line of evidence verified against the real
repository.

## Architecture

```
Source Code
   ↓  Tree-sitter parsing (language adapters)
Semantic Code Units (functions / methods / classes / ...)
   ↓  Code Embeddings (pluggable EmbeddingModel)
Vector Database (local ChromaDB)          ← indexed ONCE per repository
   ↓  Security Rule Embedding (same embedding space)
Semantic Retrieval (Top-K relevant units) ← per rule, candidate generation
   ↓
LLM Reasoning (OpenRouter)                ← security judgment, strict JSON
   ↓
Security Verdict + Grounded Evidence      ← evidence re-verified on disk
```

Responsibilities are strictly separated:

| Component | Question it answers |
|---|---|
| Tree-sitter | What are the meaningful pieces of code? |
| Vector search | Which pieces appear relevant to this security requirement? |
| LLM | Does the retrieved code actually violate the requirement? |
| Evidence validator | Did the LLM's evidence actually exist in the repository? |

## Indexer flow (Build Index button → `app.py` → `ingestion/`)

```
USER REPOSITORY
       │
       ▼
repo_dir from app.py
       │
       ▼
index_repository(repo_dir)
       │
       ▼
      root
       │
       ├──────────────────────┐
       │                      │
       ▼                      ▼
load manifest          discover files
(old cache)                  │
                             ▼
                            path
                             │
                             ▼
                   detect_language(path)
                             │
                             ▼
                          language
                             │
                             ▼
                     hash file content
                             │
              ┌──────────────┴──────────────┐
              │                             │
         unchanged                     changed/new
              │                             │
              ▼                             ▼
       reuse old units              SemanticChunker
              │                             │
              │                             ▼
              │                        Tree-sitter
              │                             │
              │                             ▼
              │                          CodeUnits
              │                             │
              │                             ▼
              │                         Embeddings
              │                             │
              │                             ▼
              │                          ChromaDB
              │                             │
              │                             ▼
              │                      update manifest
              └──────────────┬──────────────┘
                             ▼
                          next file
                             │
                             ▼
                       all files done
                             │
                             ▼
                    remove deleted files
                             │
                             ▼
                        save manifest
                             │
                             ▼
                          IndexStats
                             │
                             ▼
                            app.py
```

The manifest (content-hash cache) is what makes re-indexing incremental:
unchanged files skip Tree-sitter, embedding and ChromaDB writes entirely.

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

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env   # then fill in your key
```

## Configuration (environment variables)

| Variable | Purpose |
|---|---|
| `OPENROUTER_API_KEY` | OpenRouter API key (required for analysis) |
| `OPENROUTER_MODEL` | e.g. `openai/gpt-4o-mini` — any OpenRouter model |
| `EMBEDDING_BACKEND` | `sentence_transformers` (default, local model) or `hashing` (offline baseline) |
| `EMBEDDING_MODEL` | e.g. `all-MiniLM-L6-v2` |
| `TOP_K` | retrieved units per rule (default 8) |
| `CHROMA_DIR` / `COLLECTION_NAME` | vector DB location |

## Running

```bash
streamlit run app.py                    # UI
python -m pytest tests -q               # offline test suite (mocked LLM)
python scripts/live_test.py             # live OpenRouter benchmark run
```

The UI flow: upload/select a repository and a `security_rules.json` →
**Build Index** (files, lines, languages, code units, embeddings, vector
records) → **Analyze Security** (per-rule retrieved units with similarity
scores, status, confidence, reason, validated evidence, and token/runtime
metrics).

## Benchmark

`benchmark/source/` contains ~107 lines across Python, Java and JavaScript
with intentional SQL-injection, path-traversal and command-injection
vulnerabilities plus safe counterparts, and `benchmark/ground_truth.json`
records the expected verdict per rule per function.

## Current limitations

- Vector search does not guarantee vulnerability detection; missed
  retrieval means missed analysis (recall is bounded by Top-K).
- Retrieval is purely semantic (dense) — no keyword/symbol/call-graph
  augmentation yet.
- No cross-unit context expansion (e.g. caller → callee) yet; the
  architecture leaves room for it.
- The `hashing` embedding backend is an offline baseline, not a substitute
  for a real semantic model.
- Evidence validation checks file/line/code existence, not whether the
  evidence semantically supports the verdict.

## 100K-line scalability strategy

1. Index once: parse → semantic units → embed → store (cached by file
   content hash; unchanged files are never re-embedded).
2. Per rule: embed rule → Top-K retrieval → LLM on retrieved units only.
   LLM input size is independent of total repository size.
3. Batch embedding, persistent ChromaDB, and the hash manifest keep
   re-indexing incremental.
4. Before 100K-line testing: benchmark retrieval recall at 500/1K/10K/50K
   lines, add hybrid (keyword + dense) retrieval if recall drops, consider
   batching/async LLM calls and a cross-encoder reranker.
