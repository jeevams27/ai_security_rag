# 📘 The Verified RAG Security Analyzer — How Our Code Actually Works
### The real `.py` files of this project, and the exact journey one 100-line file takes through them — from the button you click to the verified finding that appears on screen.

**How to read this:**
- **Section A** = the map (every project file and its one job)
- **Section B** = the entry point (`app.py` — where execution starts)
- **Sections C–F** = the *journey*: we follow `bank.py` (100 lines, 2 planted bugs) hop-by-hop through the real functions, quoting the actual source of our project at each stop, showing what goes in and what comes out
- **Section G** = the data-shape cheat sheet + full call graph

Everything quoted below is the **real code of this repository** (line numbers exact).

---

# SECTION A — The map: every file, one job each

```
                          ┌────────────────────────────────────────────────┐
                          │  app.py  (Streamlit UI — the ONLY entry point) │
                          └───────────────┬────────────────┬───────────────┘
                        [Index ▼]                       [Analyze ▼]
     PHASE A — index ONCE, $0, no LLM      │      PHASE B — one loop per rule
┌─────────────────────────────────────┐    │   ┌──────────────────────────────────────┐
│ ingestion/indexer.py   (orchestrator)│    │   │ analysis/analyzer.py  (orchestrator)│
│  ├─ file_discovery.py   find files   │    │   │  ├─ retrieval/retriever.py  top-K   │
│  ├─ language_detector.py ext→lang    │    │   │  │   └─ embeddings/ + vector_store/  │
│  ├─ tree_sitter_parser.py bytes→AST  │    │   │  ├─ llm/prompts.py    build prompt  │
│  ├─ semantic_chunker.py   AST→units  │    │   │  ├─ llm/openrouter_client.py  call  │
│  ├─ embeddings/embedder.py text→vec  │    │   │  ├─ analysis/evidence_validator.py │
│  └─ vector_store/chroma_store.py     │    │   │  └─ analysis/deduplicator.py       │
│              units+vectors → .chroma/ │    │   │              verdicts → report     │
└─────────────────────────────────────┘    │   └──────────────────────────────────────┘
        shared: config.py · models/schemas.py · security rules (rules.json)
```

| File | One job | Key function(s) |
|---|---|---|
| `app.py` | UI + **the only** place that wires everything together | `prepare_repo()`, `load_rules()`, Index & Analyze button blocks |
| `config.py` | Read every knob from environment (`.env`), hard-code nothing | `Config.from_env()` |
| `models/schemas.py` | The **data shapes** every module agrees on: `CodeUnit`, `SecurityRule`, `RetrievedUnit`, `EvidenceItem`, `RuleResult`, `AnalysisMetrics` | `CodeUnit.embedding_text()`, `SecurityRule.render()` |
| `ingestion/file_discovery.py` | Walk the folder, return supported source files | `discover_source_files()`, `discover_unsupported_files()` |
| `ingestion/language_detector.py` | Extension → language key | `detect_language()` |
| `ingestion/tree_sitter_parser.py` | Language key + bytes → syntax tree; registry of 8 grammars | `TreeSitterParser.parse()`, `LANGUAGE_SPECS` |
| `ingestion/semantic_chunker.py` | Syntax tree → list of `CodeUnit` (real functions/classes) | `chunk_file()` → `chunk_source()` → `_add_unit()` |
| `ingestion/indexer.py` | **Orchestrates Phase A**; caching via manifest | `Indexer.index_repository()` |
| `embeddings/embedder.py` | Text → 384-float vector (local model, offline fallback) | `embed_texts()`, `create_embedder()` |
| `vector_store/chroma_store.py` | Persist vectors + code; cosine top-K query | `add()`, `query()` |
| `retrieval/retriever.py` | Rule text → embedding → top-K `RetrievedUnit`s | `Retriever.retrieve()` |
| `llm/prompts.py` | Build the strict system+user prompt; parse JSON back | `SYSTEM_PROMPT`, `build_user_prompt()`, `parse_llm_json()` |
| `llm/openrouter_client.py` | HTTP call to the LLM, temperature 0.0 | `OpenRouterClient.chat()` |
| `analysis/evidence_validator.py` | Fact-check every LLM citation **against disk** | `EvidenceValidator.validate()` |
| `analysis/deduplicator.py` | Collapse duplicate `(rule, file, function, line)` findings | `deduplicate_findings()` |
| `analysis/analyzer.py` | **Orchestrates Phase B** (the per-rule loop) | `SecurityAnalyzer.analyze()` → `_analyze_rule()` |

**The two orchestrators are the spine:** `Indexer.index_repository()` (Phase A) and `SecurityAnalyzer.analyze()` (Phase B). Everything else is a single-purpose helper they call — if you remember only those two names, you can navigate the codebase.

---

# SECTION B — Entry point: where execution starts (`app.py`)

The whole project has exactly **one front door**: `streamlit run app.py`. Two buttons drive it.

**B.1 — Startup (runs on every page load):**

```python
# app.py:29
config = Config.from_env()
```
`Config.from_env()` (`config.py:38-56`) reads `OPENROUTER_API_KEY`, `EMBEDDING_MODEL="all-MiniLM-L6-v2"`, `TOP_K=8`, `CHROMA_DIR=".chroma"`, `LLM_TEMPERATURE="0.0"`… from the environment/`.env`. **Why:** no secret, model or threshold is hard-coded anywhere else — one object carries every knob through the whole app.

**B.2 — The [Index ▼] button (app.py:141-157):**

```python
if index_clicked:
    repo_dir = prepare_repo()                        # uploads/ZIP/paste → a real folder on disk
    embedder = create_embedder(config)               # embedder.py:89 → MiniLM (hashing fallback)
    store = ChromaStore(persist_dir=chroma_dir, ...) # chroma_store.py:17 → .chroma/ folder
    indexer = Indexer(embedder, store, max_file_bytes=config.max_file_bytes)
    with st.spinner("Indexing ..."):
        stats = indexer.index_repository(repo_dir)   # ★ Phase A begins HERE
    st.session_state.repo_dir = str(repo_dir)
    st.session_state.index_stats = stats.to_dict()
```

These lines build the three collaborators (embedder, store, indexer) purely from config, then hand the **folder path** to `index_repository()`. From this moment the 100 lines of `bank.py` start moving.

**B.3 — The [Analyze ▼] button (app.py:190-219):**

```python
if analyze:
    rules = load_rules()          # rules.json → list[SecurityRule]
    repo_dir = prepare_repo()
    embedder = create_embedder(config)
    store    = ChromaStore(...)
    retriever = Retriever(embedder, store)            # retriever.py:15
    llm = OpenRouterClient(api_key=..., model=..., temperature=config.llm_temperature)  # 0.0
    analyzer = SecurityAnalyzer(retriever, llm, EvidenceValidator(repo_dir), top_k=int(top_k))
    report = analyzer.analyze(rules)                  # ★ Phase B begins HERE
    st.session_state.report = report.to_dict()
```

**Why constructor injection:** `SecurityAnalyzer` never imports a concrete LLM or store — it *receives* them. That's how tests pass a fake LLM in one line, and how swapping the LLM provider touches only `app.py`.

> **Mental model:** `app.py` = the order pad. `Indexer` = prep cook (Phase A, once). `SecurityAnalyzer` = line cook (Phase B, per rule). The shared ingredient between them is the `.chroma/` index Phase A wrote to disk.

---

# SECTION C — PHASE A: the journey of `bank.py` through our code

*Trace format: **HOP — `file.function()` → real code → what it does → data out → next hop.***

## Hop 1 — `ingestion/indexer.py · Indexer.index_repository()` — the conductor

```python
def index_repository(self, root):                          # indexer.py:82
    manifest = self._load_manifest()                       # cache: .chroma/manifest.json
    skipped = discover_unsupported_files(root)             # → hop 2b (visibility)
    for path in discover_source_files(root, self.max_file_bytes):  # → hop 2
        rel = path.relative_to(root).as_posix()            # "bank.py"
        language = detect_language(path)                   # → hop 3
        if language is None: continue
        file_hash = self._file_hash(path)                  # sha256 of content
        cached = manifest.get(rel)
        if cached and cached.get("hash") == file_hash:     # unchanged → skip re-embed
            stats.files_reused_from_cache += 1; continue
        if cached: self.store.delete(cached.get("unit_ids", []))  # changed → drop stale units
        units = self.chunker.chunk_file(path, rel, language)      # → hop 4
        embeddings = self.embedder.embed_texts([u.embedding_text() for u in units])  # → hop 6
        self.store.add(units, embeddings)                  # → hop 7
        new_manifest[rel] = {"hash": file_hash, "unit_ids": [u.id for u in units]}
        stats.code_units += len(units)
    self._save_manifest(new_manifest)
    return stats                                           # IndexStats → 📊 UI tab
```

**What it does:** runs the same 4-step recipe for every file — chunk → embed → store → record. **Why the sha256 manifest:** re-indexing a 10k-file repo where one file changed costs *one* file's embeddings, not 10k; switching embedding models invalidates the cache wholesale (`indexer.py:91-96`). **Why stats:** `IndexStats` (files, lines, code_units, skipped, runtime) is what the 📊 tab shows — coverage honesty is a first-class output, not a log line.

## Hop 2 — `ingestion/file_discovery.py · discover_source_files()` — find the file

```python
for dirpath, dirnames, filenames in os.walk(root_path):        # file_discovery.py:26
    dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
    for name in filenames:
        path = Path(dirpath) / name
        if path.suffix.lower() not in EXTENSION_MAP: continue  # ".py" is known → keep
        if path.stat().st_size > max_file_bytes: continue      # >1 MB → skip
        with open(path, "rb") as fh:
            if b"\x00" in fh.read(2048): continue              # binary guard → skip
        files.append(path)
return sorted(files)                                           # deterministic order
```

**Data out:** `[.../bank.py]`. **Why sorted:** identical input ⇒ identical index ⇒ reproducible runs. **Why `discover_unsupported_files()` exists separately (line 44):** files we *can't* read are collected and shown as ⚠️ warnings instead of vanishing — never let "I didn't look" look like "I looked and it's clean."

## Hop 3 — `ingestion/language_detector.py · detect_language()` — name the language

```python
return EXTENSION_MAP.get("." + name.rsplit(".", 1)[-1].lower())   # language_detector.py:38
#   "bank.py"  →  ".py"  →  "python"
```

**Data out:** the string `"python"` — the *only* language knowledge every later stage receives; parser, chunker and embedder are all language-generic. **Why:** adding a language = one `EXTENSION_MAP` entry + one `LANGUAGE_SPECS` entry, nothing else (the file's own docstring, lines 3-4, promises exactly this).

## Hop 4 — `semantic_chunker.chunk_file()` → `tree_sitter_parser.TreeSitterParser.parse()` — text becomes a tree

```python
# semantic_chunker.py:25
def chunk_file(self, path, rel_path, language):
    source = Path(path).read_bytes()
    return self.chunk_source(source, rel_path, language)

# semantic_chunker.py:29
def chunk_source(self, source, rel_path, language):
    tree = self.parser.parse(source, language)      # parser.py:124 → Tree-sitter grammar("python")
    spec = LANGUAGE_SPECS[language]                 # python → ("function_definition",), ("class_definition",)
    wanted = set(spec.function_nodes) | set(spec.class_nodes)
```

**Data out:** a Tree-sitter `Tree` over all 100 lines + the set of node types that count as units. **Why an AST, not line slices:** only the grammar knows `find_user_vulnerable` starts at line 15 and ends at line 21 — exact boundaries make both chunking and later citation possible. The grammar itself is loaded lazily (`parser.py:101-117`): first Python file → import `tree_sitter_python`, cache the `Language` forever.

## Hop 5 — `semantic_chunker._add_unit()` — the tree becomes `CodeUnit` objects

```python
# semantic_chunker.py:35-50 — recursive walk
def visit(node):
    if node.type == "decorated_definition": …unwrap decorators…
    if node.type in wanted:                          # function_definition / class_definition
        self._add_unit(node, node, source, rel_path, language, spec, units)
    for child in node.children: visit(child)         # → also finds Account's 3 methods
visit(tree.root_node)
if not units:                                       # fallback: whole file = one "module" unit
    units.append(CodeUnit(..., type="module", start_line=1, end_line=lines, ...))

# semantic_chunker.py:61-75 — one unit from one node
code = source[extent_node.start_byte:extent_node.end_byte].decode("utf-8", "replace")
units.append(CodeUnit(
    file=rel_path, language=language,
    symbol=node_name(node, source),                 # "find_user_vulnerable" (parser.py:128)
    type=type_label,                                # "function" | "class" | "method" ...
    start_line=extent_node.start_point[0] + 1,      # Tree-sitter rows are 0-based → 1-based here
    end_line=extent_node.end_point[0] + 1,
    code=self._cap(code),                           # 6000-char guard (line 77)
))
```

**Data out:** 15 `CodeUnit` records — the dataclass in `models/schemas.py:19` whose `__post_init__` mints each a stable id: `sha1("bank.py|find_user_vulnerable|15|21")[:16]`. **Why byte-slicing:** `source[start_byte:end_byte]` copies the *exact* original bytes — indentation, comments, the bug on line 19 — no reconstruction, no drift. **Why the module fallback (line 51):** a script with zero definitions is still retrievable instead of silently invisible. **Why `_cap`:** one pathological 10k-line function can't blow up the prompt budget.

## Hop 6 — `embeddings/embedder.py · embed_texts()` — code becomes numbers

```python
# indexer.py:123 — what actually gets embedded:
embeddings = self.embedder.embed_texts([u.embedding_text() for u in units])

# models/schemas.py:46 — the text form (header + code):
def embedding_text(self):
    return (f"file: {self.file}\nlanguage: {self.language}\n"
            f"{self.type}: {self.symbol}\n{self.code}")

# embedder.py:47 — the model call
def embed_texts(self, texts):
    return [[float(x) for x in vec]
            for vec in self._model.encode(list(texts), convert_to_numpy=True)]
```

**Data out:** 15 vectors × 384 floats. **Why the header prefix:** MiniLM doesn't parse Python — telling it "function: find_user_vulnerable in bank.py" frames the meaning before the code starts. **Why `embed_texts`/`embed_queries` share one model (embedder.py:1-4):** code and rules must be compared in the *same* vector space; two models would be two incompatible coordinate systems. **Why the hashing fallback (line 54):** if the model can't download, the pipeline degrades to a deterministic offline embedder instead of dying — tests run with zero network.

## Hop 7 — `vector_store/chroma_store.py · add()` — vectors hit the disk

```python
self._collection.upsert(                          # chroma_store.py:33
    ids=[u.id for u in units],                    # "ab12…" stable sha1-based ids
    embeddings=embeddings,                        # the 384-float vectors
    documents=[u.code for u in units],            # full source — needed later for the prompt
    metadatas=[u.to_metadata() for u in units],   # file/language/symbol/type/start_line/end_line
)
```

**Data out:** a persistent `code_units` collection inside `.chroma/` using **cosine** distance (`chroma_store.py:24`). **Why store the code text too:** at query time the retriever must return readable source for the prompt — no second file read, no drift if the file changed after indexing. **Why `upsert`:** re-indexing the same unit overwrites instead of duplicating.

> **Phase A ends here.** `bank.py` has been transformed: `Path → bytes → Tree → 15×CodeUnit → 15×[384 floats] → .chroma on disk`, and `IndexStats{files:1, code_units:15, …}` is returned to the UI. Zero LLM calls, zero dollars. The file now waits for a rule to come looking for it.

# SECTION D — PHASE B: the journey of a rule through our code

## Hop 8 — `app.py · load_rules()` → `models/schemas.py · SecurityRule` — rules become data

```python
# app.py:85-110 — whichever input method was chosen, it ends here:
SecurityRule.from_dict(obj)                       # schemas.py:67 — validates the 4 required fields,
                                                  # raises "missing fields: [...]" if any absent
# schemas.py:81 — how a rule will later be embedded:
def render(self):
    return (f"Security category: {self.category}\n"
            f"Severity: {self.severity}\n"
            f"Requirement: {self.requirement}")
```

**Data out:** `[SecurityRule(SQL-001…), SecurityRule(CMD-001…)]`. **Why validation at construction:** a malformed rule fails *here*, with a field name, instead of deep inside the LLM prompt. **Why `render()`:** the exact text that gets embedded — one canonical string, produced by the data class itself.

## Hop 9 — `analysis/analyzer.py · SecurityAnalyzer.analyze()` — the per-rule loop

```python
def analyze(self, rules):                          # analyzer.py:47
    for rule in rules:                             # line 50: arbitrary count, no caps, no special cases
        result = self._analyze_rule(rule, report.metrics)
        report.results.append(result)
        report.metrics.rules_analyzed += 1
    return report                                  # AnalysisReport{results, metrics}

def _analyze_rule(self, rule, metrics):            # analyzer.py:57
    retrieved = self.retriever.retrieve(rule, top_k=self.top_k)   # → hop 10
    metrics.retrievals += 1
    if not retrieved:                              # empty index → honest INCONCLUSIVE, no LLM spend
        return RuleResult(rule=rule, status="INCONCLUSIVE", ...)
    messages = [{"role": "system", "content": SYSTEM_PROMPT},      # → hop 12
                {"role": "user",   "content": build_user_prompt(rule, retrieved)}]  # → hop 11
    metrics.llm_calls += 1
    response = self.llm.chat(messages)             # → hop 13
    ...
```

**Why the loop lives here and nowhere else:** every cross-cutting concern (retrieval count, token accounting, call count) increments once per rule — `metrics.llm_calls` at line 72 *is* the number shown in the UI. **Why `if not retrieved` short-circuits:** don't burn a paid LLM call when there's nothing to judge.

## Hop 10 — `retrieval/retriever.py · Retriever.retrieve()` — rule asks the index

```python
def retrieve(self, rule, top_k=8):                 # retriever.py:20
    query_embedding = self.embedder.embed_queries([rule.render()])[0]   # same model as hop 6
    return self.store.query(query_embedding, top_k=top_k)
```

…and inside Chroma (`chroma_store.py:47-73`):

```python
result = self._collection.query(
    query_embeddings=[embedding], n_results=top_k,
    include=["documents", "metadatas", "distances"])   # cosine distances
for uid, doc, meta, dist in zip(...):
    unit = CodeUnit(file=meta["file"], ..., code=doc, id=uid)   # rebuild CodeUnit from metadata
    units.append(RetrievedUnit(unit=unit, score=1.0 - float(dist)))  # distance → similarity
```

**Data out:** 8 `RetrievedUnit{unit, score}` — for SQL-001 the top rows are `find_user_vulnerable`, `find_user_safe`, `export_users_vulnerable`… (scores illustrative). **Why `1.0 - dist`:** Chroma returns *distance* (lower=better); the UI and prompt speak *similarity* (higher=better) — this line is the unit conversion. **Why the module docstring's warning (retriever.py:3-5) matters:** this stage answers "what's relevant?", never "is it vulnerable?" — a score never appears in a verdict, only in context.

## Hop 11 — `llm/prompts.py · build_user_prompt()` — context becomes a question

```python
parts = ["SECURITY RULE:",
         f"  id: {rule.rule_id}", f"  severity: {rule.severity}",
         f"  category: {rule.category}", f"  requirement: {rule.requirement}",
         "", "RETRIEVED CODE UNITS (candidate context, may contain false positives):"]
for i, item in enumerate(retrieved, 1):             # prompts.py:59
    u = item.unit
    parts.append(f"\n--- UNIT {i} ---\nfile: {u.file}\nlanguage: {u.language}\n"
                 f"{u.type}: {u.symbol}\nlines: {u.start_line}-{u.end_line}\n"
                 f"similarity: {item.score:.4f}\ncode:\n{u.code}")
parts.append("\nDecide whether the rule is VIOLATED by the supplied code. "
             "Return strict JSON only.")
```

**Data out:** one ~1-2k-token string. **Why "may contain false positives" is printed into the prompt:** the model is *told* retrieval is only candidate generation — that single line is a hallucination speed bump. **Why numbered `UNIT n` headers:** gives the model a shared vocabulary for referencing candidates, and forces every unit to declare file/lines the evidence can later cite.

## Hop 12 — `llm/prompts.py · SYSTEM_PROMPT` — the standing law (lines 12-45)

The system prompt's load-bearing clauses, verbatim:

- *"Analyze ONLY the supplied code. Do not invent source code."*
- *"Do not invent files. Do not invent line numbers. Do not invent functions."*
- *"Semantic similarity of the retrieved code to the rule is NOT proof of a vulnerability."*
- *"Every piece of evidence MUST be verifiable against the supplied code: copy the exact code snippet and use the exact file, line, and function from the supplied code-unit headers."*
- Output = strict JSON only: `{status, confidence, reason, evidence:[{file,line,function,code,reason}]}`

**Why each exists:** clause 2 kills fabricated paths, clause 3 convicts no one for being *similar* (that's how `find_user_vulnerable` and `find_user_safe` get told apart), clause 4 is the contract the evidence validator enforces — the prompt *demands* receipts, the validator *checks* them.

## Hop 13 — `llm/openrouter_client.py · OpenRouterClient.chat()` — the only network call that costs money

```python
response = requests.post(                                   # openrouter_client.py:36
    f"{self.base_url}/chat/completions",
    headers={"Authorization": f"Bearer {self.api_key}", ...},
    json={"model": self.model, "messages": messages,
          "temperature": self.temperature},                 # 0.0 from Config (config.py:20)
    timeout=self.timeout_seconds)
if response.status_code != 200:
    raise RuntimeError(f"OpenRouter error {response.status_code}: …")   # loud, never silent
choice = data["choices"][0]["message"]
return LLMResponse(content=..., prompt_tokens=...)          # tokens flow into AnalysisMetrics
```

**Data out:** `LLMResponse{content: "<JSON text>", prompt_tokens, completion_tokens}`. **Why temperature 0.0:** rerunning the same analysis must give the same verdicts — determinism is a feature of a security tool. **Why raise on non-200 instead of returning empty:** a failed call must never masquerade as "no findings."

## Hop 14 — `llm/prompts.py · parse_llm_json()` — the answer comes back structured

```python
cleaned = text.strip()
if cleaned.startswith("```"):                              # strip fences if the model added them anyway
    cleaned = re.sub(r"^```[a-zA-Z]*\s*", "", cleaned); cleaned = re.sub(r"\s*```$", "", cleaned)
try:
    data = json.loads(cleaned)
except json.JSONDecodeError:                               # fall back: grab the {...} block
    match = _JSON_BLOCK_RE.search(cleaned)
    if not match: raise ValueError(f"LLM response is not JSON: …")
    data = json.loads(match.group(0))
```

**Data out:** a dict `{status, confidence, reason, evidence:[…]}` — or a `ValueError` that `analyzer.py:78-85` converts into an honest **INCONCLUSIVE** carrying the raw response. **Why this tolerance:** models sometimes wrap JSON in fences anyway; being 95% strict on *format* while 100% strict on *verification* is the right trade — the validator, not the parser, is where correctness is enforced.

## Hop 15 — `analysis/evidence_validator.py · EvidenceValidator.validate()` — fact-checking against disk

```python
def validate(self, evidence: dict):                        # evidence_validator.py:52
    item = EvidenceItem(file=..., line=..., function=..., code=..., reason=...)
    if not item.file:
        item.validation_reason = "rejected: no file given"; return item
    path, resolved_rel = self._resolve_file(item.file)     # exact → suffix → basename (line 34)
    if path is None:
        item.validation_reason = f"rejected: file '{item.file}' does not exist"; return item
    lines = path.read_text(...).splitlines()
    if item.line < 1 or item.line > len(lines):
        item.validation_reason = f"rejected: line {item.line} out of range …"; return item
    if item.code:
        if _normalize(item.code) not in _normalize(content):      # whitespace-insensitive
            item.validation_reason = "rejected: cited code not found in file (possible fabrication)"
            return item
    item.valid = True
    item.validation_reason = "verified against repository"
```

**Data out:** each `EvidenceItem` gains `valid=True/False` + a human-readable `validation_reason`.

**Walk the real SQL-001 claim through it:** `{file:"bank.py", line:19, code:"query = \"SELECT * … username …\""}` → `_resolve_file` finds `bank.py` ✓ → line 19 of 100 in range ✓ → normalized snippet found in normalized file ✓ → **valid, 3/3**. Now a hallucinated `{file:"payment.py", line:404}` → `_resolve_file` finds nothing → **rejected**, reason recorded.

**Why `_resolve_file`'s three-tier match (exact → suffix → basename):** LLMs write `./bank.py` or bare `bank.py`; forgiving the *path format* while never forgiving a *nonexistent file* keeps real findings and drops fakes. **Why `_normalize` (line 18):** the model may re-indent a snippet — that's sloppiness, not fabrication; fabrication is *code that appears nowhere in the file*, and that's what gets rejected.

## Hop 16 — back in `analyzer.py`: dedup + the downgrade gate (lines 104-123)

```python
unique_findings = deduplicate_findings([...])              # key: (rule_id, file, function, line)
...
if status == "VULNERABLE" and not deduped:                 # analyzer.py:120 — THE GATE
    status = "INCONCLUSIVE"
    reason += (" [downgraded: no evidence item could be verified "
               "against the repository]")
return RuleResult(rule=rule, status=status, confidence=..., reason=...,
                  evidence=deduped, retrieved=retrieved, raw_response=response.content)
```

**What it does:** collapses duplicate citations (class chunk + method chunk pointing at the same line), then applies the project's central invariant — **a VULNERABLE status with zero verified evidence cannot leave this function.** **Why here and not in the UI:** the gate sits inside the domain logic, so *every* consumer (UI, JSON download, tests) receives only gated results; presentation layers physically cannot render an unbacked conviction.

## Hop 17 — back to `app.py` (lines 221-248): the report becomes pixels

```python
report = st.session_state.report
for result in report["results"]:                           # one expander per rule
    header = f"{result['rule_id']} [{result['severity']}] {result['category']} -> {result['status']} …"
    with st.expander(header, expanded=result["status"] == "VULNERABLE"):
        st.dataframe(result["retrieved"])                  # all 8 candidates + scores
        st.dataframe(result["evidence"])                   # only validator-approved rows
cols[0].metric("Rules analyzed", m["rules_analyzed"])      # … 6 metric tiles total
cols[2].metric("LLM calls", m["llm_calls"])                # shows: 2
st.download_button("Download report (JSON)", json.dumps(report, indent=2), …)
```

**Data out:** the final screen — one expander per rule, **retrieved** and **evidence** tables side by side, six honest metrics, downloadable JSON of the same dict. **Why show `retrieved` AND `evidence`:** the audience sees exactly what was *considered* vs. what was *proven* — the pipeline's whole philosophy, rendered as UI.

# SECTION E — The data-shape cheat sheet (what the payload IS at every hop)

| After hop | File / function | The payload is… |
|---|---|---|
| 0 | `app.py` button | a folder path containing `bank.py` (100 lines of text) |
| 1-2 | `file_discovery.discover_source_files` | `list[Path]` — `[bank.py]` |
| 3 | `language_detector.detect_language` | `"python"` |
| 4 | `tree_sitter_parser.parse` | a Tree-sitter `Tree` (AST of all 100 lines) |
| 5 | `semantic_chunker.chunk_source` | `list[CodeUnit]` — 15 records, stable sha1 ids |
| 6 | `embedder.embed_texts` | `list[list[float]]` — 15 × 384 |
| 7 | `chroma_store.add` | rows in `.chroma/` (id + vector + code + metadata) |
| 8 | `load_rules` / `SecurityRule.from_dict` | `list[SecurityRule]` — 2 rules |
| 10 | `retriever.retrieve` | `list[RetrievedUnit]` — top-8 `{unit, score}` |
| 11-12 | `build_user_prompt` + `SYSTEM_PROMPT` | one chat `messages` list (system + user strings) |
| 13 | `OpenRouterClient.chat` | `LLMResponse{content: JSON text, tokens}` |
| 14 | `parse_llm_json` | `dict{status, confidence, reason, evidence[]}` |
| 15 | `EvidenceValidator.validate` | `EvidenceItem{…, valid: bool, validation_reason}` |
| 16 | `analyzer._analyze_rule` | `RuleResult` (gated: no receipts ⇒ no VULNERABLE) |
| 17 | `app.py` report block | `report dict` → screen tables + metrics + JSON download |

**One-glance call graph:**

```
app.py ──[Index]──▶ Indexer.index_repository
                       ├─ discover_source_files ─▶ [Path]
                       ├─ detect_language        ─▶ "python"
                       ├─ SemanticChunker.chunk_file ─▶ parse() ─▶ [CodeUnit]
                       ├─ embedder.embed_texts   ─▶ [[f;f;…]]
                       └─ ChromaStore.add        ─▶ .chroma/  (+ IndexStats → UI)

app.py ──[Analyze]──▶ SecurityAnalyzer.analyze ── for each rule:
                       ├─ Retriever.retrieve ─▶ embed(rule.render()) → ChromaStore.query → top-8
                       ├─ build_user_prompt + SYSTEM_PROMPT ─▶ messages
                       ├─ OpenRouterClient.chat ─▶ LLMResponse (temp 0.0)
                       ├─ parse_llm_json ─▶ verdict dict
                       ├─ EvidenceValidator.validate (×N evidence) ─▶ valid flags
                       ├─ deduplicate_findings + downgrade gate ─▶ RuleResult
                       └─ AnalysisReport.to_dict() ─▶ app.py render → screen + JSON
```

## Takeaways

1. **Two orchestrators, seventeen hops.** `Indexer.index_repository` (Phase A: text → vectors, once, free) and `SecurityAnalyzer.analyze` (Phase B: rule → verdicts, per rule, paid) — every other file is a single-purpose helper in one of those chains.
2. **The payload's shape is never a surprise** — each hop has a declared input and output type (table above), and the shapes live once in `models/schemas.py`.
3. **Trust is engineered at hops 15-16:** the prompt *demands* citations, the validator *checks them against disk*, the gate *destroys* unbacked verdicts — all before anything reaches the screen.
4. **Honesty is structural:** skipped files, empty retrievals, parse failures and token counts all surface as visible states (⚠️ / INCONCLUSIVE / metric tiles), never as silence.
5. **Extension points fall out of the design:** new language → 2 map entries; new rule → 1 JSON object; new LLM → 1 class with `.chat()`; nothing else moves.

---

*Reading path: A (map) → B (entry) → C (Phase A, hops 1-7) → D (Phase B, hops 8-17) → E (shapes + call graph). All quoted code is from this repository; line numbers exact. End of document.*






