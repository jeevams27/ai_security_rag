# 📘 The Verified RAG Security Analyzer — Complete Project Walkthrough
### One 100-line program, two security rules, every line of code and every pipeline stage explained — reading this alone is enough to understand the whole project.

---

# SECTION A — What this project is (read this first, 2 minutes)

**The problem:** LLMs asked "is this code vulnerable?" happily invent findings — they cite files that don't exist, line numbers that don't exist, code that was never written. A security report you can't verify is worse than no report.

**Our approach:** don't ask the LLM "scan everything". Instead:
1. **Index** the code locally with a parser (Tree-sitter) → real functions, not line-slices
2. For each security **rule**, retrieve only the **8 most relevant functions** with vector similarity (free, local)
3. Give the LLM **one narrow job**: judge those 8 functions against **one rule** — and if it claims a bug, it must quote the exact file + line + code
4. **Verify every quote against the real file on disk.** A claim that doesn't survive fact-checking is rejected — and a VULNERABLE verdict with zero surviving evidence is automatically downgraded to INCONCLUSIVE

**What that solves:** hallucinated findings become *structurally impossible to ship* — the only way into the report is with disk-proven receipts. Cost stays flat too: 1 rule = exactly 1 LLM call, no matter how big the repo.

**The running example:** `bank.py` (100 lines, 2 planted bugs) + `rules.json` (2 rules: SQL Injection, Command Injection). We follow it from raw text to final verified report.

**Reading order:** Section B = the 100 lines explained one by one → Section C = the 2 rules explained field by field → Section D = Phase A indexing, stage by stage with *why* → Section E = Phase B analysis, stage by stage with *why* → Section F = final report + numbers.

---

# SECTION B — The 100-line program, explained line by line

## B.1 — Lines 1-7: header — docstring, imports, constants

```python
  1  """MiniBank demo app - 100 lines with two intentional vulnerabilities."""
  2  import os
  3  import sqlite3
  4  import subprocess
  5
  6  DB = "bank.db"
  7  BACKUP_DIR = "/var/backups"
```

| Line | What it does | Why it's here / note |
|---|---|---|
| 1 | Docstring: a string describing the file | Pure documentation. Parser sees an `expression_statement`, not a unit |
| 2 | Imports `os` — file-path / OS utilities | Used by `read_statement` (line 46). Harmless by itself |
| 3 | Imports `sqlite3` — Python's SQLite driver | Gives the file **database capability** — a prerequisite for SQL injection to even be possible |
| 4 | Imports `subprocess` — run external programs | Gives the file **command-execution capability** — prerequisite for command injection |
| 5 | Blank line | Separates sections; parser ignores it |
| 6 | Constant `DB = "bank.db"` | Fixed literal, no user input → cannot be a vulnerability |
| 7 | Constant `BACKUP_DIR` | Same: fixed literal, safe |

**Key idea introduced here:** a vulnerability needs *capability* (imports at lines 3/4) + *dangerous use* (a sink) + *user input flowing into it*. Imports alone are never a finding — which is why the rules target usage, not presence.

## B.2 — Lines 10-12: `get_db()` — open a database connection

```python
10  def get_db():
11      conn = sqlite3.connect(DB)
12      return conn
```

| Line | What it does | Note |
|---|---|---|
| 10 | Defines function `get_db`, no arguments | Becomes **chunk 1** in the index |
| 11 | Opens SQLite file `bank.db`, returns a connection | Uses only the constant from line 6 — no user input, safe |
| 12 | Returns the connection | Safe |

Shared plumbing that every later DB function calls — not a finding.

## B.3 — Lines 15-21: `find_user_vulnerable()` — 🎯 BUG #1 (SQL Injection)

```python
15  def find_user_vulnerable(username):
16      # user input is glued directly into the SQL string
17      conn = get_db()
18      cur = conn.cursor()
19      query = "SELECT * FROM users WHERE name = '" + username + "'"
20      cur.execute(query)
21      return cur.fetchall()
```

| Line | What it does | Why it matters |
|---|---|---|
| 15 | Defines the function; **`username` is a parameter** — it comes from the caller (HTTP request, CLI, ...) | This is the **untrusted input** (the *source*) |
| 16 | Comment | Explains the bug; becomes part of the indexed chunk text |
| 17 | Gets a DB connection via `get_db()` | Setup, safe |
| 18 | Creates a cursor — the object that executes SQL | Setup, safe |
| 19 | Builds the SQL by **string concatenation**: `'...name = \'' + username + '\''` | 🎯 **THE BUG.** If `username` = `x' OR '1'='1`, the query becomes `...name = 'x' OR '1'='1'` — the attacker controls the *structure* of the SQL |
| 20 | Executes the attacker-influenced query | The **sink** — the poisoned query actually runs |
| 21 | Returns all matching rows | Consequence: an attacker can read every user's row |

**The bug in one sentence:** line 19 mixes *data* (username) into *code* (the SQL string), so input can rewrite code. The SQL-001 verdict will cite lines 19-20 as evidence.

## B.4 — Lines 24-28: `find_user_safe()` — the safe twin (why we get ZERO false positives)

```python
24  def find_user_safe(username):
25      conn = get_db()
26      cur = conn.cursor()
27      cur.execute("SELECT * FROM users WHERE name = ?", (username,))
28      return cur.fetchall()
```

| Line | What it does | Why it matters |
|---|---|---|
| 24 | Same signature as line 15 — same untrusted input | Retrieval ranks this chunk **#2** for the SQL rule (it *looks* similar) |
| 25-26 | Same setup as lines 17-18 | — |
| 27 | Executes the query with a **`?` placeholder**, `username` passed separately | 🟢 **Parameterized query**: the driver keeps code and data apart — nothing in `username` can ever become SQL syntax |
| 28 | Returns rows | Safe |

This function exists so you can *watch* the model distinguish intent: ranked #2 by similarity (same meaning-space) but **acquitted** by the verdict (safe pattern). Similarity ≠ guilt.

## B.5 — Lines 31-35: `run_backup_vulnerable()` — 🎯 BUG #2 (Command Injection)

```python
31  def run_backup_vulnerable(filename):
32      # user input goes straight into a shell command
33      cmd = "tar czf backup.tar.gz " + filename
34      subprocess.run(cmd, shell=True)
35      return "done"
```

| Line | What it does | Why it matters |
|---|---|---|
| 31 | Function takes **`filename`** from the caller | Untrusted input (*source*) |
| 32 | Comment | Included in the chunk text |
| 33 | Builds a shell command by concatenating `filename` | 🎯 **THE BUG.** `filename` = `x; rm -rf /` produces `tar czf backup.tar.gz x; rm -rf /` — a second command the attacker wrote |
| 34 | Runs the string **through the shell** (`shell=True`) | The **sink**: `/bin/sh -c "..."` executes *everything* in the string, separators included |
| 35 | Returns `"done"` | (Always "done" — even when it wasn't) |

**The bug in one sentence:** line 33 lets input write shell *syntax* (`;`, `&&`, backticks) and line 34 executes it with a shell that honors those separators. CMD-001's evidence will cite lines 33-34.

## B.6 — Lines 38-42: `run_backup_safe()` — safe twin #2

```python
38  def run_backup_safe(filename):
39      if not filename.isalnum():
40          raise ValueError("bad filename")
41      subprocess.run(["tar", "czf", "backup.tar.gz", filename])
42      return "done"
```

| Line | What it does | Why it matters |
|---|---|---|
| 38 | Same signature — same untrusted input | Ranks **#2** for CMD-001 |
| 39 | Rejects any filename containing characters other than letters/digits | 🟢 **Allow-list validation** kills `;`, `&&`, `` ` `` before they matter |
| 40 | Raises an error for bad input | Fails closed, not open |
| 41 | Runs `tar` with a **list of arguments** — no `shell=True` | 🟢 Even if validation were bypassed, there is no shell to interpret `;` — `filename` is only ever *one argument* |
| 42 | Returns `"done"` | Safe (and honest) |

Two independent defenses (validate + no shell) — the LLM must recognize *both* to acquit this one.

## B.7 — Lines 45-48: `read_statement()` — neutral file read

```python
45  def read_statement(month):
46      path = os.path.join("/data", month + ".txt")
47      with open(path) as f:
48          return f.read()
```

| Line | What it does | Note |
|---|---|---|
| 45 | Takes `month` from the caller | Untrusted input — *could* be path traversal (`../../etc/passwd`) |
| 46 | Joins `/data` + `month` + `.txt` | ⚠️ Looks risky, but **no SQL/OS-command rule covers this** — the rules decide what's in scope |
| 47-48 | Opens the file, returns contents | Neutral under our 2 rules |

**Teaching point:** the analyzer applies *the rules you give it*. This would light up under a Path Traversal rule (just add it to `rules.json` — zero code, see Section E). Under SQL-001/CMD-001 it correctly stays quiet — scoping, not a miss.

## B.8 — Lines 51-53: `hash_pin()` — hashing a PIN

```python
51  def hash_pin(pin):
52      import hashlib
53      return hashlib.sha256(pin.encode()).hexdigest()
```

| Line | What it does | Note |
|---|---|---|
| 51 | Takes a PIN | Sensitive data, but *handling* it isn't either rule's concern |
| 52 | Imports hashlib **inside** the function | Valid Python; parser still sees one `function_definition` [51-53] |
| 53 | SHA-256 hash of the PIN | 🟢 Hashing, not logging — the right direction; out of both rules' scope |

## B.9 — Lines 56-71: `class Account` — business logic with validation

```python
56  class Account:
57      def __init__(self, owner, balance=0):
58          self.owner = owner
59          self.balance = balance
60
61      def deposit(self, amount):
62          if amount <= 0:
63              raise ValueError("amount must be positive")
64          self.balance += amount
65          return self.balance
66
67      def withdraw(self, amount):
68          if amount > self.balance:
69              raise ValueError("insufficient funds")
70          self.balance -= amount
71          return self.balance
```

| Lines | What it does | Note |
|---|---|---|
| 56 | Declares class `Account` | Becomes **chunk 8** (whole class, 16 lines) |
| 57-59 | Constructor: stores owner + starting balance | Plain assignment, safe. Also its own **chunk 9** |
| 61-65 | `deposit`: rejects non-positive amounts, adds to balance | 🟢 Input validation done right — what "safe" looks like in business logic |
| 67-71 | `withdraw`: rejects overdrafts, subtracts | 🟢 Fails closed; no SQL, no shell → irrelevant to both rules |

**Why class-chunk AND method-chunks exist:** retrieval may surface the *whole class* (broad context) or *one method* (sharp context). The dedup step later collapses them if both cite the same line.

## B.10 — Lines 74-78: `monthly_report()` — string formatting

```python
74  def monthly_report(accounts):
75      lines = []
76      for acc in accounts:
77          lines.append(f"{acc.owner}: {acc.balance}")
78      return "\n".join(lines)
```

| Line | What it does | Note |
|---|---|---|
| 74 | Takes a list of Account objects | — |
| 75-76 | Empty accumulator, loop over accounts | — |
| 77 | Formats `"name: balance"` via f-string | 🟢 Attributes only — no SQL, no shell |
| 78 | Joins with newlines, returns | Neutral |

## B.11 — Lines 81-85: `ping_host_safe()` — defense-in-depth example

```python
81  def ping_host_safe(host):
82      allowed = {"8.8.8.8", "1.1.1.1"}
83      if host not in allowed:
84          raise ValueError("host not allowed")
85      subprocess.run(["ping", "-c", "1", host])
```

| Line | What it does | Note |
|---|---|---|
| 81 | Takes `host` — untrusted input, headed for a command | Would be a classic command-injection source |
| 82 | Hard **allow-list** of exactly two IPs | 🟢 Strongest defense: anything not listed is rejected |
| 83-84 | Enforces the allow-list, raises otherwise | Fails closed |
| 85 | Runs ping as an argument **list** (no `shell=True`) | 🟢 Second independent defense |

**Why it's in the file:** retrieval ranks it **#3** for CMD-001 (subprocess + user input!) and the model must still acquit it. Three subprocess functions retrieved, one guilty — that's the precision story.

## B.12 — Lines 88-95: `export_users_vulnerable()` — SQL *without* user input

```python
88  def export_users_vulnerable():
89      conn = get_db()
90      cur = conn.cursor()
91      cur.execute("SELECT * FROM users")
92      rows = cur.fetchall()
93      with open("users.csv", "w") as f:
94          for r in rows:
95              f.write(",".join(map(str, r)) + "\n")
```

| Line | What it does | Note |
|---|---|---|
| 89-90 | Connection + cursor (same as always) | — |
| 91 | Executes a **fixed literal** query | 🟢 Despite the scary name: no input in the query. SQL-001 forbids concatenating *user-controlled input* — here there is none |
| 92 | Fetches all rows | — |
| 93-95 | Writes rows to `users.csv` | 🟢 No SQL construction, no shell — out of both rules' scope |

**Why it's in the file:** retrieval ranks it **#3** for SQL-001 (full of SQL keywords). A naive keyword scanner screams; the name "vulnerable" is a deliberate trap for the LLM — the strict prompt ("similarity/name is NOT proof") is what beats it.

## B.13 — Lines 98-99: `greet()` — input but no sink

```python
98  def greet(name):
99      return f"Hello, {name}!"
```

| Line | What it does | Note |
|---|---|---|
| 98 | Takes a name — untrusted input | Source exists... |
| 99 | Returns a greeting | ...but there is **no dangerous sink**. Input alone is not a vulnerability |

**Closing lesson of Section B:** both rules need *input flowing into a sink*. Input without a sink (99), SQL without input (91), subprocess with an allow-list (82-85) — all safe. The analyzer must reproduce exactly this reasoning; Section E shows it doing so.

### Section B summary map

| Lines | Function | Chunk | Role in the demo |
|---|---|---|---|
| 1-7 | header / imports | — (file level) | capability: sqlite3 + subprocess imported |
| 10-12 | `get_db` | 1 | plumbing |
| **15-21** | `find_user_vulnerable` | **2** | 🎯 **SQL bug (line 19)** |
| 24-28 | `find_user_safe` | 3 | safe twin — must be acquitted |
| **31-35** | `run_backup_vulnerable` | **4** | 🎯 **CMD bug (lines 33-34)** |
| 38-42 | `run_backup_safe` | 5 | safe twin — must be acquitted |
| 45-48 | `read_statement` | 6 | out-of-scope trap (path usage) |
| 51-53 | `hash_pin` | 7 | neutral |
| 56-71 | `Account` + 3 methods | 8-11 | business logic, validation done right |
| 74-78 | `monthly_report` | 12 | neutral |
| 81-85 | `ping_host_safe` | 13 | subprocess but allow-listed — acquit |
| 88-95 | `export_users_vulnerable` | 14 | SQL but input-free — acquit |
| 98-99 | `greet` | 15 | input but no sink — acquit |

**Ground truth:** exactly 2 violations (line 19 → SQL-001, lines 33-34 → CMD-001); all 13 other units must come back clean. That is the bar the pipeline must clear.

# SECTION C — The two rules, field by field

```json
[
  { "rule_id": "SQL-001", "severity": "HIGH", "category": "SQL Injection",
    "requirement": "User-controlled input must not be concatenated directly into SQL queries." },
  { "rule_id": "CMD-001", "severity": "CRITICAL", "category": "Command Injection",
    "requirement": "User-controlled input must not be passed directly into operating-system command execution." }
]
```

| Field | SQL-001 value | What it's used for (why the field exists) |
|---|---|---|
| `rule_id` | `"SQL-001"` | Stable identifier — appears in every prompt and verdict, and is the first key of dedup `(rule_id, file, function, line)`. A finding can be referenced forever |
| `severity` | `"HIGH"` | Business impact — drives 🔴/🟡 color and report sorting. It **ranks**, it does **not detect**: judging happens against the requirement text, severity only annotates the result |
| `category` | `"SQL Injection"` | Rendered into the rule text before embedding (E.1). A strong semantic anchor: "SQL Injection" sits close to `execute`, `query`, `cursor` in meaning-space, steering retrieval |
| `requirement` | *"User-controlled input must not be concatenated directly into SQL queries."* | **The actual test.** One complete, unambiguous sentence: what must not happen (concatenating input into SQL), to what (SQL queries), controlled by whom (user input). This sentence does all the retrieval and judging work |

**CMD-001, same anatomy:** `CRITICAL` (impact: full server compromise) · `Command Injection` (anchor: shell, subprocess, system) · the requirement bans passing input *directly* into OS command execution — note "**directly**": validated + allow-listed input (`ping_host_safe`, lines 81-85) doesn't violate it. That nuance is exactly what the model must apply.

**Why rules are data, not code:** a third rule (Path Traversal — which would light up line 46!) is one appended JSON object: zero code changes, Phase B just runs one more iteration of the same loop. The rules file *is* the product's configuration surface.

**Two design notes worth saying out loud:**
- Requirements are written as *prohibitions with a subject* ("user-controlled input must not...") — that's what lets the model acquit `export_users_vulnerable` (no subject → no violation) and convict `find_user_vulnerable` (subject flows into SQL).
- Nothing in the JSON references `bank.py` — rules are **repo-agnostic**; the same file audits any codebase.

---

# SECTION D — PHASE A: Indexing the 100 lines (runs ONCE, local, $0, no LLM)

*Each stage: **What happens → Input/Output → Why it exists (what breaks without it).***

## D.1 — Stage 1: File discovery (`ingestion/file_discovery.py`)

**What happens:** walks the chosen folder recursively; collects candidate source files; skips `node_modules/`, `.git/`, binaries, files over 1 MB; then runs a second pass listing *unsupported* files (e.g. `.php`) with reasons.

**Input → Output:** folder path → `[bank.py]` (accepted) + `skipped_files=[...]` (reported).

**Why it exists:** the classic scanner failure is the **silent blind spot** — unsupported files ignored, green banner shown, user believes everything was checked. The skipped list flows to the UI as a ⚠️ yellow warning; if *zero* supported files remain, a ❌ red error blocks the run and names the 18 supported extensions. You can never mistake "I didn't look" for "I looked and it's clean."

## D.2 — Stage 2: Language detection (`ingestion/language_detector.py`)

**What happens:** pure lookup — `bank.py → ".py" → EXTENSION_MAP[".py"] → "python"`.

**Input → Output:** filename → `"python"` (or `None` → the file joins the skipped list, never silently dropped).

**Why it exists:** everything downstream is **language-generic**. The parser, chunker and embedder never see a filename — only a language key that selects the right Tree-sitter grammar. Adding Rust later = one map entry + one grammar package; zero pipeline changes. Without this indirection, every stage would grow language-specific `if` statements.

## D.3 — Stage 3: Parsing to an AST (`ingestion/tree_sitter_parser.py`)

**What happens:** Tree-sitter's Python grammar converts the 100 lines of text into a syntax tree. Every node carries its type (`function_definition`, `block`, `binary_operator`, ...) and exact position: `start_byte`, `end_byte`, `start_point`, `end_point` (row/column).

**Input → Output:** `bank.py` bytes → tree rooted at `module [1-100]` containing 15 definition nodes.

**Why it exists:** lines alone don't know *meaning*. Line 15 is just "the 15th line" — the tree knows line 15 is **the start of a named unit `find_user_vulnerable` ending at line 21**. That boundary knowledge enables:
1. **Semantic chunking** (D.4) — no arbitrary windows cut mid-function
2. **Precise citations** — the report can say `function: find_user_vulnerable`, not just `line 19`
3. **Language-agnostic operation** — the chunker doesn't parse; it reads node-type lists from `LANGUAGE_SPECS`

Without the AST we'd get fixed-size chunks: half a function here, half there, and verdicts citing line numbers with no idea which function owns them.

## D.4 — Stage 4: Semantic chunking (`ingestion/semantic_chunker.py`)

**What happens:** recursively walks the tree; for every node whose type is in the language's definition set (`function_definition`, `class_definition`) it emits one `CodeUnit`, slicing exact source via `start_byte:end_byte` and stamping `start_line = start_point[0]+1`, `end_line = end_point[0]+1`. Decorators unwrapped; methods emitted both inside the class chunk and standalone; a file with no definitions becomes one `module` unit (lines 1-N); units over 6000 chars truncated with a marker.

**Input → Output:** tree → **15 `CodeUnit` records** (map in Section B): `{id, file, language, symbol, type, start_line, end_line, code, sha1}`.

**Why it exists:** the LLM judges **complete functions**, never line-slices. `find_user_vulnerable` whole (comment + setup + bug + execute) gives the model everything to reason about data flow — a window starting at line 17 hides the signature; one starting at 19 hides the parameter. **Chunk = the smallest unit that still makes sense to a judge.** The fallback chain (module-unit / truncation) guarantees the pipeline **never produces a silently empty or partial index**.

## D.5 — Stage 5a: Embedding (`embeddings/embedder.py`)

**What happens:** each chunk's code is wrapped with a metadata header (`file: bank.py / language: python / function: find_user_vulnerable`) and pushed through **all-MiniLM-L6-v2** — a small sentence-embedding model running **locally** — producing one 384-float vector per chunk.

**Input → Output:** 15 texts → 15 × 384 numbers.

**Why it exists:** vectors turn *meaning* into *math*. Once "SQL query built by concatenating username" and the rule "input must not be concatenated into SQL queries" are points in the same space, finding relevant code is a distance calculation — microseconds, no API, no keyword lists. The **header wrap** matters because MiniLM doesn't parse Python: telling it "this is a function called find_user_vulnerable in bank.py" frames the embedding for what it is. And **local + free is non-negotiable**: you must afford to embed every chunk *and* every rule at zero cost — only the judging step is allowed to spend money.

## D.6 — Stage 5b: Vector storage (`vector_store/chroma_store.py`, orchestrated by `ingestion/indexer.py`)

**What happens:** `indexer.py` runs D.1→D.5 per file and stores into a **ChromaDB** collection on disk — per chunk: `id` (`bank.py::find_user_vulnerable::15-21`), the 384-float embedding, the header-wrapped document text, and metadata `{file, symbol, unit_type, start_line, end_line, sha1}`. It then returns `IndexStats {files_indexed:1, files_skipped:0, chunks:15, languages:{python:1}}`.

**Input → Output:** vectors + texts → persistent searchable collection + honest statistics.

**Why it exists:** the index is a **rebuildable side-artifact, never the source of truth** — the repo on disk is, and that's exactly what the evidence validator checks against later (E.5). Storing the *text* alongside the vector means retrieval returns full readable code to the prompt with no file re-reads at query time. `IndexStats` powers the 📊 Indexing tab so the operator sees precisely what was — and wasn't — indexed.

> **Phase A finished:** 100 lines → 15 chunks → 15 vectors on disk. **$0, 0 LLM calls, ~2 seconds.** The index never changes again unless you rebuild it.

---

# SECTION E — PHASE B: Analyzing against the rules (one loop per rule)

## E.1 — Stage 6: Rule → searchable text → vector

**What happens:** each rule JSON object is rendered into one rule text:

```
Rule SQL-001 (severity: HIGH) — SQL Injection
Requirement: User-controlled input must not be concatenated directly into SQL queries.
```

…and embedded with **the same MiniLM model** used for code → one 384-dim rule vector.

**Input → Output:** one `rules.json` object → one query vector.

**Why it exists / what breaks without it:** retrieval can only compare *like with like* — code and rules must live in the same 384-dim meaning-space, which requires the identical model (two different models = two incompatible coordinate systems; every comparison would be noise). Including `category` + `severity` in the rendered text gives the embedder semantic anchors ("SQL Injection" → close to `execute`, `cursor`, `query`). **Why one rule at a time:** each rule is an independent question — bundling them lets the model answer one confidently and hallucinate the rest, and destroys per-rule attribution.

## E.2 — Stage 7: Cosine-similarity retrieval, top-k=8 (`retrieval/retriever.py`)

**What happens:** computes `cosine(rule_vector, chunk_vector)` against all 15 chunks, keeps the **8 highest**. Illustrative ranking for SQL-001: `find_user_vulnerable ~0.91 · find_user_safe ~0.89 · export_users_vulnerable ~0.84 · Account/withdraw ~0.72 · read_statement ~0.68 …` (exact numbers depend on the model run; the *ordering* is the point).

**Input → Output:** rule vector → ordered top-8 `CodeUnit`s with scores.

**Why it exists / what breaks without it:**
- **Why vectors, not grep:** grep matches *spelling* — it cannot tell a parameterized call (line 27) from a concatenated one (line 19); that difference is structural, not lexical. Cosine compares *meaning*.
- **Why top-8, not all 15:** every extra irrelevant chunk is noise the model can over-fit to — and the deliberate traps (ranks #2 and #3) only prove precision if the model sees them *and still acquits*.
- **Retrieval ≠ verdict:** a high score only means *relevant to discuss*. `find_user_safe` scores ~0.89 and still gets acquitted — that pair (retrieved + acquitted) is what shows the pipeline is judging, not ranking.

## E.3 — Stage 8: The strict judge prompt (`llm/prompts.py`)

**What happens:** builds one prompt containing: system rules (your ONLY source of truth is the code shown; similarity/function name is not proof; VULNERABLE requires user-controlled input *actually reaching* the dangerous sink; return strict JSON), the rule (id/severity/category/requirement), and the numbered candidates (id, file, function, lines, code). One **Verdict** per candidate: `verdict` (VULNERABLE|SAFE|INCONCLUSIVE), `reason`, `evidence` {file, function, line, snippet} — evidence **required** for VULNERABLE.

**Input → Output:** 1 rule + 8 chunks → one prompt (~1-2k tokens) → strict JSON verdicts.

**Why it exists / what breaks without it:**
- **The evidence requirement is the whole trick:** a verdict with no quote is a rumor; forcing `file + function + line + snippet` turns every claim into something a machine can fact-check (E.5).
- **The anti-hallucination clauses are load-bearing:** without "similarity is not proof", the model convicts `find_user_safe` (rank #2!) and `export_users_vulnerable` (named *vulnerable*!). Without "input must *reach* the sink", it convicts `greet` (has input) or `ping_host_safe` (has subprocess).
- **Why only 8 chunks:** a bounded, focused prompt — the same ~1-2k-token question regardless of repo size.

## E.4 — Stage 9: The LLM call (`llm/llm_client.py`)

**What happens:** sends the prompt to the configured provider (local `ollama` by default; OpenAI / OpenRouter / Ollama selectable in the UI) at **temperature 0.0**, parses the JSON verdicts from the response, and treats parse failures as errors — never as verdicts.

**Input → Output:** prompt → raw completion → `list[Verdict]`.

**Why it exists / what breaks without it:**
- **Temperature 0:** the report must be reproducible — rerunning doesn't shuffle verdicts, and creative drift (the hallucination engine) is minimized.
- **Pluggable provider:** the pipeline only needs "prompt in, JSON out" — swap local models for privacy or frontier models for depth without touching any other stage.
- **1 call per rule:** rules are independent → parallelizable, individually attributable ("CMD-001 said X"), and cost scales with *rules*, never with lines of code.

## E.5 — Stage 10: Evidence validation — the differentiator (`validation/evidence_validator.py`)

**What happens:** takes each VULNERABLE verdict's evidence and, **without trusting the LLM at all**, runs three checks against the real file on disk:
1. **File exists?** — `bank.py` present in the repo
2. **Line exists & matches?** — open the file, take the cited line: does it actually contain the quoted snippet?
3. **Function matches?** — does the cited function name actually own that line (checked via chunk metadata ranges)?

Then the **downgrade gate**: VULNERABLE + 0 surviving evidence → verdict forced to INCONCLUSIVE (evidence counts 0-3 recorded either way).

**What the checks catch (illustrative outcomes):** exact match → ✅ confirmed · wrong line, real code → ⚠️ line corrected, downgraded · file doesn't exist → ❌ rejected · wrong function → ⚠️ corrected · snippet appears nowhere → ❌ fabricated → rejected.

**Input → Output:** verdicts with claims → verdicts with **disk-verified** evidence + counts.

**Why it exists / what breaks without it:** this is the line between "LLM opinions" and "findings". The model has no idea what's actually on your disk — it may quote line 19 perfectly but name the wrong file, or invent a plausible-sounding line entirely; only an on-disk check catches that. The **downgrade gate** guarantees the report can never contain an unbacked VULNERABLE — the worst case for a fabricated claim is that it disappears, never that it ships. SAFE verdicts are untouched (they make no claim needing proof).

## E.6 — Stage 11: Dedup, compress, assemble

**What happens:** findings dedupe on `(rule_id, file, function, line)` — the class-chunk and method-chunk citing the same line collapse into one. Each surviving finding compresses into `RuleResult {rule_id, severity, category, requirement, status, findings, evidence_checked, evidence_confirmed, chunks_considered}`. One `RuleResult` per rule.

**Input → Output:** raw verdicts → clean per-rule results (no duplicate lines, no runaway token counts).

**Why it exists / what breaks without it:** without dedup, a bug inside a class counts twice (class chunk + method chunk both cite it) and the severity count lies. Without compression, storing each verdict's full essay bloats the report and UI. `chunks_considered=8` makes the retrieval budget visible in the output — you can audit *how much context* each judgment stood on.

> **Phase B finished:** 2 rules × 1 call each = **2 LLM calls total** → 2 `RuleResult`s → exactly **2 confirmed findings** (SQL-001 @ line 19, CMD-001 @ lines 33-34) — matching ground truth, with all 13 other units acquitted or never surfaced.

---

# SECTION F — The finished report & what it proves

## F.1 — Final output (what the audience sees)

```
Security Analysis Report   ·   100 lines analyzed · 15 chunks · 2 rules · 2 LLM calls
──────────────────────────────────────────────────────────────────
🔴 HIGH    SQL-001        SQL Injection        find_user_vulnerable  bank.py:19
          evidence 3/3 confirmed — "SELECT * FROM users WHERE name = '" + username + "'"
🔴 CRITICAL CMD-001       Command Injection    run_backup_vulnerable bank.py:33-34
          evidence 3/3 confirmed — cmd = "tar czf backup.tar.gz " + filename
──────────────────────────────────────────────────────────────────
12 other units: SAFE / out of scope     skipped files: none (⚠️ shown if any)
```

*(Report fields, metrics and evidence rows are exact; similarity scores and token counts elsewhere in this document are illustrative — structure, files, line numbers and module references are exact.)*

## F.2 — Why this report is trustworthy (the chain, end to end)

| Guarantee | Enforced by |
|---|---|
| Findings cite **real files, real lines, real code** | Stage 10 evidence validator reads the disk; unverifiable claims rejected |
| A bug is never reported **without receipts** | Downgrade gate: VULNERABLE + 0 evidence → INCONCLUSIVE |
| Safe-but-similar code is **not falsely accused** | Strict prompt clauses (similarity/name ≠ proof) + safe twins in the file |
| Nothing was **silently skipped** | File discovery's unsupported list + `IndexStats` in the UI |
| Cost doesn't grow with repo size | Retrieval caps context at 8 chunks; **1 LLM call per rule** |
| Reproducible verdicts | Temperature 0.0, strict JSON, deterministic local embedding |

## F.3 — The one-slide recap (say this, they understand the project)

> We take a security **rule** as plain JSON, embed it, retrieve the **8 most relevant code functions** from a local vector index (built once from an AST — so chunks are real functions, not line-slices), and ask an LLM to judge **one rule against those 8 functions**, forcing it to quote file + line + code for every VULNERABLE claim. A validator then **fact-checks every quote against the real file on disk** and downgrades anything unproven. Result: `bank.py` — 100 lines, 2 planted bugs — yields **exactly 2 confirmed findings at lines 19 and 33-34**, zero false positives, 2 total LLM calls, and a report where every line can be clicked back to the code that earned it.

## F.4 — The extension story (30 seconds, if asked)

- **New language:** add one entry to `EXTENSION_MAP` + one Tree-sitter grammar → chunker/parser/embedder untouched (they read language-generic `LANGUAGE_SPECS`).
- **New rule:** append one JSON object to `rules.json` → one more loop iteration, one more LLM call, zero code.
- **New LLM provider:** implement "prompt in → JSON out" → every other stage untouched.
- **Bigger repo:** Phase A scales linearly with files; Phase B scales with *rules*, never with LOC — that's the whole point of retrieval.

---

*Reading path: Section A (what/why) → B (every line of the 100) → C (every field of the 2 rules) → D (index, every stage with why) → E (analyze, every stage with why) → F (report & proof). End of document.*








