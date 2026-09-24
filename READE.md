# 📘 Why Each Piece Exists — The RAG Security Analyzer, Explained by Problem
### A presentation-ready walkthrough of this project: every stage told as **Problem → What we built → What breaks without it**, following one 100-line file (`bank.py`) and two rules through the real code.

**How to read / present this:**
- **Part 0** — the story of the whole project in one page
- **Part 1** — Phase A (indexing): why each ingestion stage exists
- **Part 2** — Phase B (analysis): why each analysis stage exists
- **Part 3** — the cross-cutting "whys" (config, schemas, wiring, honesty)
- **Part 4** — the one-table summary + speaker's recap

Every stage below maps to real files in this repository; file names and line numbers are exact.

---

# PART 0 — The story in one page

**The problem:** Teams want an LLM to check their code against security rules. Ask a raw chatbot "does this repo have SQL injection?" and it *answers confidently* — quoting files that don't exist, line numbers it never saw, functions it invented. The answer sounds right and is **unverifiable**. That's hallucination, and in security review, a fabricated finding (or a missed real one) is worse than no answer.

**What we built:** a pipeline that never lets the LLM see the whole repo, never lets its claims reach the user unchecked, and never guesses when it can measure:

1. **Index once, locally** — turn the repository into semantic code units and vectors (Phase A). Free, no LLM.
2. **Retrieve narrowly** — for each security rule, fetch only the top-8 *relevant* code units (not the whole repo).
3. **Reason under strict rules** — one LLM call per rule, temperature 0.0, forced to cite file/line/code or say nothing.
4. **Verify against disk** — every citation is fact-checked against the real files; unverifiable verdicts are **downgraded**, not displayed.

**The trust guarantee this buys:** the tool can still be *wrong about interpretation*, but it can no longer **invent evidence** — a VULNERABLE verdict physically cannot leave the analyzer without at least one citation that exists on disk. That single invariant is the project's reason for existing.

**The cast (one line each):**

| File | Why it exists in one sentence |
|---|---|
| `app.py` | The only entry point — turns buttons into the two orchestrator calls |
| `config.py` | So no secret/model/threshold is ever hard-coded |
| `models/schemas.py` | So every module speaks the same data shapes |
| `ingestion/indexer.py` | Phase A conductor: text → vectors, once |
| `ingestion/file_discovery.py` | So we find source files *and honestly report* the ones we skip |
| `ingestion/language_detector.py` | So one extension maps to one language, nothing more |
| `ingestion/tree_sitter_parser.py` | So "what is a function" is answered by a grammar, not a regex |
| `ingestion/semantic_chunker.py` | So chunks are real constructs (functions/classes), not line slices |
| `embeddings/embedder.py` | So code and rules live in one comparable vector space |
| `vector_store/chroma_store.py` | So the index survives restarts and answers top-K questions |
| `retrieval/retriever.py` | So relevance is *candidate generation*, never a verdict |
| `llm/prompts.py` | So the model is commanded to cite or stay silent |
| `llm/openrouter_client.py` | So the one paid, external call is small, logged, deterministic |
| `analysis/evidence_validator.py` | So every claim is checked against the actual repository |
| `analysis/deduplicator.py` | So one bug isn't reported three times |
| `analysis/analyzer.py` | Phase B conductor: rule → gated verdict |

---

# PART 1 — PHASE A (indexing): why each stage exists

*The payload: `bank.py`, a 100-line file with 2 planted bugs. It enters at the [Index ▼] button, which calls `Indexer.index_repository()` — and that function's whole job is to make the file *findable by meaning* later.*

## Stage A1 — File discovery · `file_discovery.discover_source_files()`

- ⚠️ **Problem:** A repo folder contains everything — `.git` history, `node_modules`, binaries, images, 200 MB logs. Feed those to a parser and you crash or waste hours; *ignore* them silently and users don't know what wasn't analyzed.
- 🔧 **What we built:** a walker that filters by known extensions, skips vendor/VCS directories and oversized files, guards against binaries (`b"\x00"` sniff), returns files **sorted** for reproducibility — plus a sibling `discover_unsupported_files()` that reports everything it refused to read.
- 💥 **What breaks without it:** indexing crawls through dependencies, dies on a corrupted file, or — worse — a `.txt` config with secrets is silently ingested while an unsupported `.rs` file is silently *never analyzed* and nobody is told.

## Stage A2 — Language detection · `language_detector.detect_language()`

- ⚠️ **Problem:** 8 supported languages must flow through identical downstream code; if every stage re-implements "what file is this?", adding a language becomes an 8-file edit.
- 🔧 **What we built:** one `EXTENSION_MAP` (`.py → python`, …). The result is a single string that the parser, chunker and embedder all consume.
- 💥 **What breaks without it:** no stable contract between discovery and parsing — Tree-sitter would guess grammars per call site, and "add Rust support" (2 map entries, by design) turns into touching the whole pipeline.

## Stage A3 — Tree-sitter parsing · `tree_sitter_parser.TreeSitterParser.parse()`

- ⚠️ **Problem:** Security rules care about *functions and classes*. Regex can't reliably find where `find_user_vulnerable` begins and ends (decorators, nesting, multi-line signatures, comments that look like code). Wrong boundaries → wrong line numbers → citations that fail validation later.
- 🔧 **What we built:** a registry of 8 grammar adapters (`LANGUAGE_SPECS`), loaded lazily and cached; `parse()` turns raw bytes into a real syntax tree. Symbol names come from the AST (`node_name()`), with per-language fallbacks (C declarator chains, Go type specs).
- 💥 **What breaks without it:** chunk boundaries become guesswork — evidence cites line 19 when the function actually starts at line 17, and the *entire verification layer's* line numbers become unreliable. Also: the "safe twin next to the bug" layout in `bank.py` (line 24 vs line 15) could not be told apart structurally.

## Stage A4 — Semantic chunking · `semantic_chunker.chunk_source()`

- ⚠️ **Problem:** LLMs and embedding models have limited context. Splitting files into arbitrary N-line windows cuts functions in half, destroys the "which rule does this function violate" mapping, and makes retrieved snippets meaningless on their own.
- 🔧 **What we built:** walk the AST, emit one `CodeUnit` per real construct (function/method/class), byte-slicing the *exact* original source (`source[start_byte:end_byte]` — comments, indentation, bugs included), each with a stable sha1-based id and 1-based line range. Fallback: a file with no constructs becomes one `module` unit so it's still retrievable. A 6000-char cap keeps one giant function from blowing the prompt budget.
- 💥 **What breaks without it:** retrieval returns fragments of half-functions; the LLM judges code missing its signature or its body; and evidence snippets no longer match the file on disk, so even *true* findings get rejected by the validator.

## Stage A5 — Embedding · `embeddings/embedder.embed_texts()`

- ⚠️ **Problem:** "SQL injection" and `cursor.execute(f"SELECT ...")` share **zero keywords** — a search engine matches the first, misses the second. Rules and code must be comparable by *meaning*.
- 🔧 **What we built:** one local model (all-MiniLM-L6-v2, 384 dims) embeds both code units *and* rules — code gets a metadata header prefix (`file: … / function: …`) so the model knows what it's reading. `embed_texts` and `embed_queries` are guaranteed to be the same space by an abstract base class. A deterministic hashing backend exists so tests and offline runs never depend on a model download.
- 💥 **What breaks without it:** you're back to keyword search — the rule "commands executed via shell" never retrieves `os.system(f"ping {host}")`; or worse, documents and queries are embedded by *different* models, and cosine similarity compares incompatible coordinate systems (retrieval silently returns garbage).

## Stage A6 — Vector store + cache · `chroma_store.add()` / `indexer` manifest

- ⚠️ **Problem:** Embedding is the slowest part of indexing; re-embedding 10k unchanged files every run is unacceptable. And the index must answer "top-8 most similar" instantly at query time.
- 🔧 **What we built:** Chroma (local, persistent, cosine) stores vector + full code text + metadata per unit — so query time needs no file reads. A sha256 manifest records each file's content hash + unit ids: unchanged file → skip entirely; changed file → delete stale units, re-embed just that one; **different embedding model → wipe everything** (mixing spaces would corrupt retrieval).
- 💥 **What breaks without it:** every analysis run pays full indexing cost; edited files leave ghost units of deleted code that still get retrieved and "verified" against nothing; or vectors from two models coexist and similarity scores become meaningless.

> **End of Phase A:** `bank.py` is now 15 `CodeUnit`s + 15 vectors on disk, `IndexStats` returned to the UI (files, units, skipped, runtime), **$0 spent, 0 LLM calls**. The file waits for a rule to come looking for it.

---

# PART 2 — PHASE B (analysis): why each stage exists

*The payload now: `security_rules.json` (2 rules — SQL-001, CMD-001) + the index from Phase A. The [Analyze ▼] button calls `SecurityAnalyzer.analyze(rules)` — its job is to produce verdicts **that can be trusted more than the model that wrote them**.*

## Stage B1 — Rules as data · `load_rules()` → `SecurityRule.from_dict()`

- ⚠️ **Problem:** If rules live in code (`if rule == "SQL": ...`), every new check is a code change, a re-review, a redeploy. Hard-coding 2 rules also *lies* about the design — the tool claims to be general.
- 🔧 **What we built:** rules arrive as JSON, validated into `SecurityRule` (4 required fields; missing field → named error at load time, not a broken prompt later). `render()` produces the one canonical text that gets embedded.
- 💥 **What breaks without it:** analysts can't add checks without a developer; a typo'd rule silently retrieves nonsense; and the same rule could render differently in different paths, making retrieval irreproducible.

## Stage B2 — The per-rule loop · `SecurityAnalyzer.analyze()`

- ⚠️ **Problem:** A report must cover N rules with consistent accounting — how many calls, tokens, retrievals — and scale past the 2 demo rules without redesign.
- 🔧 **What we built:** a plain `for rule in rules` loop, no caps, no special cases; every metric increments inside the loop, so the numbers on screen *are* the numbers from the code. Empty retrieval short-circuits to INCONCLUSIVE **before** any paid call.
- 💥 **What breaks without it:** metrics drift into estimates, adding a third rule needs a new branch, and an empty index burns money asking the LLM about nothing.

## Stage B3 — Top-K retrieval · `retriever.retrieve()` → `chroma_store.query()`

- ⚠️ **Problem:** Feeding the LLM the whole repo is slow, expensive, and *hurts* accuracy — the model drowns in irrelevant code. Sending nothing means it invents.
- 🔧 **What we built:** embed the rule (`rule.render()`) in the *same* space as Phase A, ask Chroma for the 8 closest units (cosine distance → similarity via `1.0 - dist`). The docstring enforces the philosophy: retrieval answers *"what's relevant?"* — never *"is it vulnerable?"* Scores only order context; they never decide verdicts.
- 💥 **What breaks without it:** context overflow on real repos (cost ×10), or the subtle failure — the LLM treats "top-ranked" as "guilty" and convicts `find_user_safe` because it *looks like* its vulnerable twin next door.

## Stage B4 — The strict prompt · `prompts.SYSTEM_PROMPT` + `build_user_prompt()`

- ⚠️ **Problem:** Left free-form, an LLM answers any security question fluently and fabricates: invented paths, invented lines, code "remembered" instead of read.
- 🔧 **What we built:** a system prompt that *forbids* exactly those moves — analyze only supplied code; don't invent files/lines/functions; **similarity is not proof**; insufficient context → INCONCLUSIVE; every evidence item must copy the exact snippet and header fields. The user prompt frames units as *"candidate context, may contain false positives"* and demands strict JSON back.
- 💥 **What breaks without it:** you have a chatbot again — plausible prose, unverifiable claims — precisely the failure this project eliminates. Note the design: the prompt *demands* receipts, but we still don't *trust* it (see B6).

## Stage B5 — One deterministic call · `OpenRouterClient.chat()`

- ⚠️ **Problem:** The LLM layer is the only paid, external, non-repeatable dependency — it must fail loudly, cost a predictable amount, and give the same answer twice.
- 🔧 **What we built:** exactly one HTTP call per rule at `temperature 0.0` (deterministic), 120 s timeout, non-200 → `RuntimeError` (never a silent empty response that reads as "no findings"), token usage returned and accumulated into `AnalysisMetrics`.
- 💥 **What breaks without it:** flaky runs where yesterday's VULNERABLE is today's SAFE for no reason; provider errors swallowed into green checkmarks; and cost nobody can explain to a budget holder.

## Stage B6 — Evidence validation · `EvidenceValidator.validate()`

- ⚠️ **Problem:** **This is the core problem of the entire project.** The LLM's JSON looks identical whether it was derived from your code or hallucinated. Display its citations unchecked and one invented file/line destroys the tool's credibility forever.
- 🔧 **What we built:** every evidence item is fact-checked against the real repository — three gates: (1) the file exists (exact → suffix → basename resolution: forgiving *path format*, never nonexistent files); (2) the line number is in range; (3) the cited snippet actually appears in the file (whitespace-normalized — re-indentation passes, **invented code fails**). Each item gets `valid` + a readable `validation_reason`; rejected claims are kept and shown, not hidden.
- 💥 **What breaks without it:** the tool becomes "a chatbot with a UI" — one day it flags `payment.py:404`, a file you don't have, and everything it ever said becomes suspect too. **Without this stage there is no difference between this project and asking ChatGPT.**

## Stage B7 — Dedup + the downgrade gate · `analyzer._analyze_rule()` lines 104-123

- ⚠️ **Problem:** Two failure modes sneak past a perfect validator: (1) the *same* bug cited twice — via the class chunk and the method chunk — inflating apparent severity; (2) the LLM says VULNERABLE but **every** evidence item fails validation — a confident verdict with zero receipts.
- 🔧 **What we built:** dedup on `(rule_id, file, function, line)`, then the gate — four lines:

```python
if status == "VULNERABLE" and not deduped:
    status = "INCONCLUSIVE"
    reason += " [downgraded: no evidence item could be verified against the repository]"
```

  It lives *inside* the analyzer, not the UI, so every consumer — screen, JSON download, tests — can only ever see gated results.
- 💥 **What breaks without it:** a new export path forgets the check and renders an unbacked conviction; duplicates make 1 bug look like 3; the report's VULNERABLE count stops meaning anything.

## Stage B8 — Report assembly & display · `AnalysisReport.to_dict()` → `app.py`

- ⚠️ **Problem:** A report that shows only conclusions forces readers to trust the tool blindly; estimated (or missing) metrics invite skepticism.
- 🔧 **What we built:** each rule's result carries **retrieved** (all 8 candidates + scores) *and* **evidence** (only validator-approved rows) side by side; six metric tiles (rules, retrievals, LLM calls, prompt/completion tokens, runtime) are counted, not estimated; full report downloads as JSON; VULNERABLE expanders open by default.
- 💥 **What breaks without it:** no auditor can tell "candidate" from "proven"; "2 LLM calls" becomes marketing copy instead of a countable fact; and the demo's central claim — *these two citations survived disk verification* — has nowhere to be shown.

---

# PART 3 — The cross-cutting "whys" (things that shape *every* stage)

## C1 — Config objects instead of constants · `config.py`

- ⚠️ **Problem:** Hard-coded API keys leak; hard-coded models/thresholds make every experiment a code edit.
- 🔧 **What we built:** one `Config.from_env()` dataclass — key, model, temperature, top-K, dirs, chunk caps — read from `.env` once at startup.
- 💥 **Without it:** secrets end up in git, and "try top-K=16" means editing source, committing, and re-reviewing a diff that shouldn't have changed.

## C2 — Shared data shapes · `models/schemas.py`

- ⚠️ **Problem:** 16 files passing dicts around means every module guesses the others' keys; a renamed field becomes a runtime `KeyError` three hops from the change.
- 🔧 **What we built:** all contracts live in one file — `CodeUnit`, `SecurityRule`, `RetrievedUnit`, `EvidenceItem`, `RuleResult`, `AnalysisMetrics`, plus `ALLOWED_STATUSES`. The module docstring states the design: *everything downstream of Tree-sitter treats every language identically; the only contract is the `CodeUnit` shape.*
- 💥 **Without it:** the parser, retriever, validator and UI each redefine "a finding" slightly differently — and the inconsistencies only surface at runtime, mid-demo.

## C3 — Constructor injection · `app.py` wiring

- ⚠️ **Problem:** If `SecurityAnalyzer` did `import OpenRouterClient` itself, tests would need real API keys, and swapping providers would mean editing domain logic.
- 🔧 **What we built:** `app.py` constructs the embedder, store, retriever, LLM and validator, then *hands them in*. `SecurityAnalyzer` only knows interfaces.
- 💥 **Without it:** the test suite's fake LLM (and the offline hashing embedder) become impossible; CI needs secrets; the project can't run in a classroom with no internet.

## C4 — Honesty as a feature (visible failure states)

- ⚠️ **Problem:** The dangerous output of a security tool isn't a wrong verdict — it's **silence that looks like success**: skipped files nobody mentioned, a provider outage rendered as "0 findings", unparseable LLM output dropped quietly.
- 🔧 **What we built:** every failure has a visible state — ⚠️ skip list in the UI; `INCONCLUSIVE` with a reason string (including the parse-failure text and the downgrade note); `RuntimeError` on HTTP errors; metric tiles for *everything* (even when `LLM calls = 0`, the report says so); scores labeled illustrative.
- 💥 **Without it:** users over-trust green checkmarks — the exact failure mode (confident, unverifiable answers) the project was created to fix, reproduced *by the tool itself*.

---

# PART 4 — The one-table summary (speaker's recap)

| Stage | Problem it solves | What breaks without it |
|---|---|---|
| A1 File discovery | Repo = noise (binaries, vendor, huge files) | Slow runs, crashes, silent coverage gaps |
| A2 Language detect | One contract for 8 languages | Every stage guesses; new language = 8 edits |
| A3 Tree-sitter parse | Real function/class boundaries | Wrong line numbers → validator rejects true findings |
| A4 Semantic chunk | Context limits; meaningful units | Half-functions retrieved; snippets can't be verified |
| A5 Embedding | Meaning-based rule↔code matching | Keyword search misses `os.system(f…)`; mixed spaces = garbage |
| A6 Store + cache | Fast queries; no re-embedding | Full cost every run; ghost units of deleted code |
| B1 Rules as data | Checks change without code changes | Analysts blocked; irreproducible rendering |
| B2 Per-rule loop | Counted metrics; N rules | Estimated numbers; 3rd rule = redesign |
| B3 Top-8 retrieval | Right context, not all context | Cost explosion *or* top-ranked = presumed guilty |
| B4 Strict prompt | Forbids fabrication up front | Back to a chatbot with invented citations |
| B5 Temp-0.0 call | Deterministic, loud, budgeted | Non-reproducible verdicts; silent provider failures |
| B6 Evidence validator | **Citations checked against disk** | **Indistinguishable from asking ChatGPT** |
| B7 Dedup + gate | No duplicates; no receipt-less verdicts | 1 bug → 3 findings; VULNERABLE with zero proof |
| B8 Report | Candidates vs proven, counted metrics | Blind trust; un-auditable claims |
| C1-C4 Cross-cutting | Config / schemas / injection / honesty | Leaked keys, runtime KeyError, untestable, false calm |

**The 30-second version, for the last slide:**

> We took a repo that a raw LLM would *guess* about, and built a pipeline where the repo is indexed once by grammar-accurate parsers, each rule retrieves only what's relevant, the LLM reasons under strict orders at temperature zero, and — the part that matters — **every sentence it cites is verified against the actual files before you're allowed to see it.** If verification finds nothing, the verdict is downgraded in code, not by policy. That's why the output is evidence, not vibes.

**Suggested flow when presenting:** Part 0 (2 min) → click through the app: Index, then Analyze (2 min) → one stage at a time using the ⚠️/🔧/💥 triple (8-10 min) → Part 4 table as the recap slide (2 min) → the 30-second version as the closer.

---

*All file names and line numbers refer to this repository. Similarity scores and token counts mentioned are illustrative unless measured in a live run. End of document.*



