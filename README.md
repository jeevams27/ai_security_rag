# AI Security RAG Analyzer

A language-agnostic, retrieval-augmented security analyzer. Given a source
repository and any number of structured security rules, it finds the code
relevant to each rule and uses an LLM to decide whether that code violates
the rule — with every cited line of evidence verified against the real
repository.

## Architecture - step by step

The system works in two phases:

- Phase 1 (INDEX) runs once per repository.
- Phase 2 (ANALYZE) runs once per security rule.

```text
Step 1. User opens app.py (Streamlit UI)
   |
   v
Step 2. PHASE 1 - INDEX the repository
   |
   v
Step 3. PHASE 2 - ANALYZE the index against security rules
   |
   v
Step 4. User reads the findings + downloads the JSON report
```

### PHASE 1 - INDEX (Build Index button -> ingestion/)

This phase converts raw source files into searchable vectors.
It runs once, and re-runs incrementally when files change.

```text
Step 1. User picks a repository folder
   |
   v
Step 2. app.py passes repo_dir to index_repository(repo_dir)
   |
   v
Step 3. Load the manifest (cache of last index)
   |
   v
Step 4. Discover all source files in the folder
   |
   v
Step 5. For each file, detect its language
   |
   v
Step 6. Hash the file content
   |
   v
Step 7. Compare hash with manifest
   |
   +-----> UNCHANGED -> reuse old code units -> skip to next file
   |
   +-----> CHANGED or NEW -> continue to Step 8
   |
   v
Step 8. SemanticChunker splits the file
   |
   v
Step 9. Tree-sitter parses each chunk
   |
   v
Step 10. Build CodeUnits (functions, methods, classes)
   |
   v
Step 11. Embed each CodeUnit into a vector
   |
   v
Step 12. Store vectors in ChromaDB
   |
   v
Step 13. Update the manifest with the new hash
   |
   v
Step 14. Move to next file (repeat Step 5 to Step 13)
   |
   v
Step 15. Remove deleted files from ChromaDB
   |
   v
Step 16. Save manifest to disk
   |
   v
Step 17. Return IndexStats to app.py
        (files, lines, languages, units, embeddings, records)
```

Why the manifest matters: unchanged files are never re-parsed,
re-embedded, or re-stored. That is what keeps re-indexing fast.

### PHASE 2 - ANALYZE (Analyze Security button -> analysis/ + llm/)

This phase runs once per rule, using only the index built in Phase 1.

```text
Step 1. Load security_rules.json (1, 5, 50 or 100 rules - same code path)
   |
   v
Step 2. Pick one rule
   |
   v
Step 3. Embed the rule requirement into the same vector space as the code
   |
   v
Step 4. Retrieve Top-K relevant CodeUnits from ChromaDB
        (default K = 8, semantic candidate generation only)
   |
   v
Step 5. Send rule + retrieved code to the LLM (OpenRouter, strict JSON)
   |
   v
Step 6. LLM returns one verdict per rule:
        VULNERABLE or SAFE or INCONCLUSIVE, with confidence,
        reason, and cited evidence (file, line, function, code)
   |
   v
Step 7. Evidence validator checks every cited item on disk:
        - does the file exist in the repository?
        - is the line number real?
        - does the quoted code actually appear near that line?
        - does the named function exist?
        Unverified items are dropped.
   |
   v
Step 8. If verdict is VULNERABLE but no evidence survived,
        downgrade verdict to INCONCLUSIVE
   |
   v
Step 9. Deduplicate repeated evidence
   |
   v
Step 10. Repeat Step 2 to Step 9 for the next rule
   |
   v
Step 11. Build the final report
        - screen shows VULNERABLE findings only, fully open:
          why it is vulnerable + file/line/function/code table
          + what NOT to do + what to do instead
        - JSON download keeps everything (all verdicts, retrieved units,
          evidence, token usage, runtime)
```

Key idea: vector search only proposes candidates, the LLM judges them,
and the validator confirms the cited code really exists before it is shown.
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

