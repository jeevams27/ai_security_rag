# 🎓 How the Verified RAG Security Analyzer Works — Complete Walkthrough
**One 100-line file. Two security rules. Every stage, every tree node, every number — no need to open the project.**

**How to read this deck:** everything shown with `✔` is real output of the project's modules (module name given in each stage header). Numbers marked *illustrative* are plausible sample values; structure is always exact.

---

## Slide 1 — Input A: `bank.py` (exactly 100 lines, 2 hidden bugs)

```python
  1  """MiniBank demo app - 100 lines with two intentional vulnerabilities."""
  2  import os
  3  import sqlite3
  4  import subprocess
  5
  6  DB = "bank.db"
  7  BACKUP_DIR = "/var/backups"
  8
  9
 10  def get_db():
 11      conn = sqlite3.connect(DB)
 12      return conn
 13
 14
 15  def find_user_vulnerable(username):
 16      # user input is glued directly into the SQL string
 17      conn = get_db()
 18      cur = conn.cursor()
 19      query = "SELECT * FROM users WHERE name = '" + username + "'"
 20      cur.execute(query)
 21      return cur.fetchall()
 22
 23
 24  def find_user_safe(username):
 25      conn = get_db()
 26      cur = conn.cursor()
 27      cur.execute("SELECT * FROM users WHERE name = ?", (username,))
 28      return cur.fetchall()
 29
 30
 31  def run_backup_vulnerable(filename):
 32      # user input goes straight into a shell command
 33      cmd = "tar czf backup.tar.gz " + filename
 34      subprocess.run(cmd, shell=True)
 35      return "done"
 36
 37
 38  def run_backup_safe(filename):
 39      if not filename.isalnum():
 40          raise ValueError("bad filename")
 41      subprocess.run(["tar", "czf", "backup.tar.gz", filename])
 42      return "done"
 43
 44
 45  def read_statement(month):
 46      path = os.path.join("/data", month + ".txt")
 47      with open(path) as f:
 48          return f.read()
 49
 50
 51  def hash_pin(pin):
 52      import hashlib
 53      return hashlib.sha256(pin.encode()).hexdigest()
 54
 55
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
 72
 73
 74  def monthly_report(accounts):
 75      lines = []
 76      for acc in accounts:
 77          lines.append(f"{acc.owner}: {acc.balance}")
 78      return "\n".join(lines)
 79
 80
 81  def ping_host_safe(host):
 82      allowed = {"8.8.8.8", "1.1.1.1"}
 83      if host not in allowed:
 84          raise ValueError("host not allowed")
 85      subprocess.run(["ping", "-c", "1", host])
 86
 87
 88  def export_users_vulnerable():
 89      conn = get_db()
 90      cur = conn.cursor()
 91      cur.execute("SELECT * FROM users")
 92      rows = cur.fetchall()
 93      with open("users.csv", "w") as f:
 94          for r in rows:
 95              f.write(",".join(map(str, r)) + "\n")
 96
 97
 98  def greet(name):
 99      return f"Hello, {name}!"
100
```

## Slide 2 — Input B: `rules.json` (2 rules, pure data — nothing about them is hardcoded in code)

```json
[
  { "rule_id": "SQL-001", "severity": "HIGH", "category": "SQL Injection",
    "requirement": "User-controlled input must not be concatenated directly into SQL queries." },
  { "rule_id": "CMD-001", "severity": "CRITICAL", "category": "Command Injection",
    "requirement": "User-controlled input must not be passed directly into operating-system command execution." }
]
```

**Ground truth (what a human auditor knows):** line 19 violates SQL-001 · lines 33-34 violate CMD-001 · everything else is safe. The analyzer must find exactly this, with proof, zero false alarms.

---

## Slide 3 — Module Map: which file does what (the whole project in 13 rows)

| # | Stage | Module | Reads | Writes |
|---|---|---|---|---|
| 1 | Find files | `ingestion/file_discovery.py` | repo folder | file list + skipped list |
| 2 | Detect language | `ingestion/language_detector.py` | filename | `"python"` |
| 3 | Parse to AST | `ingestion/tree_sitter_parser.py` | source text | tree |
| 4 | Chunk tree | `ingestion/semantic_chunker.py` | tree | 15 `CodeUnit`s |
| 5 | Orchestrate index | `ingestion/indexer.py` | file list | `IndexStats` |
| 5 | Embed | `embeddings/embedder.py` | texts | 384-dim vectors |
| 5 | Store | `vector_store/chroma_store.py` | vectors | Chroma collection |
| 6-7 | Rule render + retrieve | `retrieval/retriever.py` | rules | top-8 units |
| 8 | Build prompt | `llm/prompts.py` | rule + units | messages |
| 8 | Call LLM | `llm/openrouter_client.py` | messages | strict JSON |
| 9 | Validate evidence | `analysis/evidence_validator.py` | JSON + disk | validity flags |
| 10 | Dedup + verdicts | `analysis/deduplicator.py`, `analysis/analyzer.py` | all results | `AnalysisResult` |
| UI | Streamlit app | `app.py`, `ui_explorer.py` | everything | report on screen |

Data shapes are frozen in `models/schemas.py`; knobs (`TOP_K=8`, chunk size, model names) in `config.py`.

---

## Slide 4 — PHASE A, Stage 1-2: Discovery + Language Detection

**`file_discovery.py`** walks the folder, finds `bank.py`; skips `node_modules/`, `.git/`, binaries, files over 1 MB, and records any unsupported extension for the UI warning. Result: **1 file accepted, 0 skipped.**

**`language_detector.py`:**
```
"bank.py" -> splitext -> ".py" -> EXTENSION_MAP[".py"] -> "python"
```
`"python"` selects which Tree-sitter grammar parses the file. No hardcoded `.py` logic anywhere, adding a new language = adding an extension + a grammar.

---

## Slide 5 — PHASE A, Stage 3: The Abstract Syntax Tree of all 100 lines (`tree_sitter_parser.py`)

Tree-sitter runs the **Python grammar** over the text. Every node carries a type and a `[start-end]` line range. This is the complete top-level tree (expression leaves collapsed; the two vulnerable functions expanded fully on the next slide):

```
module  [1-100]
├── expression_statement: string (docstring)        [1]
├── import_statement (os)                           [2]
├── import_statement (sqlite3)                      [3]
├── import_statement (subprocess)                   [4]
├── assignment: DB = "bank.db"                      [6]
├── assignment: BACKUP_DIR = "/var/backups"         [7]
│
├── function_definition get_db                      [10-12]   <- chunk 1
│   ├── parameters: ()                              [10]
│   └── block                                       [11-12]
│       ├── expression_statement: sqlite3.connect   [11]
│       └── return_statement: conn                  [12]
│
├── function_definition find_user_vulnerable       [15-21]   <- chunk 2  (SQL BUG)
├── function_definition find_user_safe             [24-28]   <- chunk 3
├── function_definition run_backup_vulnerable      [31-35]   <- chunk 4  (CMD BUG)
├── function_definition run_backup_safe            [38-42]   <- chunk 5
├── function_definition read_statement             [45-48]   <- chunk 6
├── function_definition hash_pin                   [51-53]   <- chunk 7
│
├── class_definition Account                       [56-71]   <- chunk 8
│   ├── function_definition __init__               [57-59]   <- chunk 9
│   ├── function_definition deposit                [61-65]   <- chunk 10
│   └── function_definition withdraw               [67-71]   <- chunk 11
│
├── function_definition monthly_report             [74-78]   <- chunk 12
├── function_definition ping_host_safe             [81-85]   <- chunk 13
├── function_definition export_users_vulnerable    [88-95]   <- chunk 14
└── function_definition greet                      [98-99]   <- chunk 15
```

**Key idea:** an AST is not a flat list of lines, it knows *boundaries*. Line 15 is not just line 15, it is the **start of a named unit** `find_user_vulnerable` that ends at line 21. That is what makes semantic chunking possible.

### Slide 5b — The two vulnerable subtrees, expanded to the last node

These are the exact nodes the chunker, the retriever, and the validator will point at later:

```
function_definition find_user_vulnerable   [15-21]        <- CHUNK 2
├── identifier (name): find_user_vulnerable              [15]
├── parameters                                           [15]
│   └── identifier: username          (the untrusted input!)
└── block                                 [15-21]
    ├── comment "# user input is glued..."               [16]
    ├── expression_statement: conn = get_db()            [17]
    ├── expression_statement: cur = conn.cursor()        [18]
    ├── expression_statement                             [19]  *** SQL BUG ***
    │   └── assignment: query = <string concat>
    │       └── binary_operator "+"                      [19]
    │           ├── string "SELECT * FROM users WHERE name = '"
    │           ├── identifier username    (input flows here)
    │           └── string "'"
    ├── expression_statement: cur.execute(query)         [20]  (the sink)
    └── return_statement: cur.fetchall()                 [21]
```

```
function_definition run_backup_vulnerable   [31-35]       <- CHUNK 4
├── identifier (name): run_backup_vulnerable             [31]
├── parameters
│   └── identifier: filename           (the untrusted input!)
└── block                                 [31-35]
    ├── comment "# user input goes straight..."          [32]
    ├── expression_statement                             [33]  *** CMD BUG ***
    │   └── assignment: cmd = <string concat>
    │       └── binary_operator "+"
    │           ├── string "tar czf backup.tar.gz "
    │           └── identifier filename   (input flows here)
    ├── expression_statement                             [34]  (the sink)
    │   └── call: subprocess.run(cmd, shell=True)
    │       ├── argument: cmd
    │       └── keyword_argument: shell=True
    └── return_statement: "done"                         [35]
```

Reading the tree top-down, **the bug pattern is visible as structure**: *untrusted `identifier` -> `string concat` -> dangerous `call`*, all inside one `block`. That is exactly what the LLM is asked to find later — and exactly what the validator re-checks.

---

## Slide 6 — PHASE A, Stage 4: Chunking — where the tree gets cut (`semantic_chunker.py`)

**Rule:** the chunker walks the AST and emits one `CodeUnit` per "named definition" node — `function_definition` and `class_definition` (methods inside a class are emitted both standalone and inside the class chunk). Everything else (imports, top-level assignments, comments) is never a chunk of its own; it belongs to the file, not to a unit.

Cut points on our tree:

| AST node cut | Chunk produced | Source lines | Code text taken from the tree |
|---|---|---|---|
| `function_definition get_db` | chunk 1 | 10-12 | `def get_db(): ...` (3 lines) |
| `function_definition find_user_vulnerable` | chunk 2 🎯 | 15-21 | full 7 lines incl. line 19 |
| `function_definition find_user_safe` | chunk 3 | 24-28 | 5 lines |
| `function_definition run_backup_vulnerable` | chunk 4 🎯 | 31-35 | full 5 lines incl. 33-34 |
| `function_definition run_backup_safe` | chunk 5 | 38-42 | 5 lines |
| `function_definition read_statement` | chunk 6 | 45-48 | 4 lines |
| `function_definition hash_pin` | chunk 7 | 51-53 | 3 lines |
| `class_definition Account` | chunk 8 | 56-71 | whole class, 16 lines |
| `function_definition __init__` | chunk 9 | 57-59 | 3 lines |
| `function_definition deposit` | chunk 10 | 61-65 | 5 lines |
| `function_definition withdraw` | chunk 11 | 67-71 | 5 lines |
| `function_definition monthly_report` | chunk 12 | 74-78 | 5 lines |
| `function_definition ping_host_safe` | chunk 13 | 81-85 | 5 lines |
| `function_definition export_users_vulnerable` | chunk 14 | 88-95 | 8 lines |
| `function_definition greet` | chunk 15 | 98-99 | 2 lines |

**100 lines -> 15 chunks -> 0 lines lost** (line ranges tile the functions; imports/assignments live at file level). Oversized units (over `MAX_CHUNK_CHARS`) are split at statement boundaries; parse failures fall back to fixed line-windows — never a silent empty index.

Each chunk becomes one immutable record (`models/schemas.py`):

```json
{
  "id": "bank.py::find_user_vulnerable::15-21",
  "file": "bank.py", "language": "python",
  "symbol": "find_user_vulnerable", "unit_type": "function",
  "start_line": 15, "end_line": 21,
  "code": "def find_user_vulnerable(username):\n    # user input ...\n    ...",
  "sha1": "a3f9c2..."
}
```

---

## Slide 7 — PHASE A, Stage 5: Embed + Store (`embeddings/embedder.py` → `vector_store/chroma_store.py`)

Each chunk's code is wrapped with a metadata header so the vector "knows what it is" even out of context:

```
file: bank.py
language: python
function: find_user_vulnerable
def find_user_vulnerable(username):
    # user input is glued directly into the SQL string
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    ...
```

That text goes through **`all-MiniLM-L6-v2`** (runs locally on CPU, free, 384-dimensional) and becomes the chunk's "meaning fingerprint":

```
[0.018, -0.221, 0.442, 0.095, ... ]   <- exactly 384 numbers
```

`indexer.py` stores all 15 into a **ChromaDB collection** on disk. Per-chunk layout:

| Chroma field | Example value (chunk 2) |
|---|---|
| `id` | `bank.py::find_user_vulnerable::15-21` |
| `embedding` | the 384-float vector above |
| `document` | the header-wrapped code text (re-shown to the LLM) |
| `metadata` | `{file, language, symbol, unit_type, start_line: 15, end_line: 21, sha1}` |

`indexer.py` also returns `IndexStats`: `files_indexed=1, files_skipped=0, chunks=15, languages={python:1}` → shown in the 📊 Indexing tab.

> Phase A is now finished: **$0 spent, 0 LLM calls, ~2 seconds.** The index never changes again unless you re-index.

---

## Slide 8 — PHASE B begins, Rule 1: SQL-001 (`retrieval/retriever.py`)

### Step 6 — The rule becomes a vector (same embedder!)

The rule is rendered as text and embedded with the **same model** — rule and code must live in one shared meaning-space:

```
Security category: SQL Injection
Severity: HIGH
Requirement: User-controlled input must not be concatenated directly into SQL queries.
        |
        v  all-MiniLM-L6-v2 (local, free)
[0.131, 0.204, -0.087, ... ]   <- the rule's 384-dim fingerprint
```

### Step 7 — Compare against all 15 chunks: cosine similarity

Chroma computes, for the rule vector `q` and each chunk vector `c`:

```
             q · c            sum(qi * ci)
cos(q, c) = -------  =  ----------------------------
          |q| |c|        sqrt(sum(qi^2)) * sqrt(sum(ci^2))

range -1..1  ->  1 = "same meaning", 0 = "unrelated"
```

All 15 scores, sorted (scores *illustrative* but realistic for MiniLM):

| Rank | Chunk | Lines | Score | The bug? |
|---|---|---|---|---|
| 1 | `find_user_vulnerable` | 15-21 | **0.61** | 🎯 YES (line 19) |
| 2 | `find_user_safe` | 24-28 | 0.55 | no - safe twin |
| 3 | `export_users_vulnerable` | 88-95 | 0.48 | no - SQL but no user input |
| 4 | `get_db` | 10-12 | 0.41 | no |
| 5 | `read_statement` | 45-48 | 0.33 | no |
| 6 | `run_backup_vulnerable` | 31-35 | 0.31 | no (that's rule 2's bug) |
| 7 | `hash_pin` | 51-53 | 0.27 | no |
| 8 | `monthly_report` | 74-78 | 0.22 | no |
| 9-15 | 7 remaining chunks | | < 0.20 | dropped (below TOP_K) |

**Top-K = 8** (`config.py`) — only these 8 travel to the LLM.

⚠️ **Teaching point:** rank 1 = the bug, rank 2 = the safe twin, rank 6 = the *other* rule's bug. **Retrieval is a candidate filter, never a verdict.** Similarity says "look here", not "guilty".

---

## Slide 9 — Step 8: The ONE LLM call for SQL-001 (`llm/prompts.py` + `llm/openrouter_client.py`)

### The prompt that is actually sent (abridged — the real one embeds all 8 full code texts):

```
SYSTEM (temperature 0.0, strict JSON):
  You are a security-analysis reasoning engine.
  STRICT RULES:
  - Analyze ONLY the supplied code. Do not invent source code.
  - Do not invent files, line numbers, or functions.
  - Semantic similarity is NOT proof of a vulnerability.
  - Every evidence item MUST copy the exact file, line, and snippet.
  - Respond with STRICT JSON ONLY:
    {status, confidence, reason, evidence[{file,line,function,code,reason}]}

USER:
  SECURITY RULE: id: SQL-001, severity: HIGH, category: SQL Injection
  requirement: User-controlled input must not be concatenated directly
  into SQL queries.

  RETRIEVED CODE UNITS (8):
  --- UNIT 1 --- file: bank.py | function: find_user_vulnerable
                 lines: 15-21 | similarity: 0.61
      def find_user_vulnerable(username):
          # user input is glued directly into the SQL string
          conn = get_db()
          cur = conn.cursor()
          query = "SELECT * FROM users WHERE name = '" + username + "'"
          cur.execute(query)
          return cur.fetchall()
  --- UNIT 2 --- file: bank.py | function: find_user_safe | lines: 24-28 | 0.55
      ... (units 3-8 likewise, full source)
```

### What comes back (deterministic at temp 0.0; realistic example):

```json
{
  "status": "VULNERABLE",
  "confidence": 0.93,
  "reason": "find_user_vulnerable concatenates the 'username' parameter directly into the SQL string on line 19 and executes it on line 20. find_user_safe in the same file demonstrates the correct parameterized form, confirming no sanitization happens anywhere for the vulnerable variant.",
  "evidence": [
    { "file": "bank.py", "line": 19, "function": "find_user_vulnerable",
      "code": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"",
      "reason": "user-controlled username concatenated into SQL string" },
    { "file": "bank.py", "line": 20, "function": "find_user_vulnerable",
      "code": "cur.execute(query)",
      "reason": "the tainted query is executed" }
  ]
}
```

What the LLM was really doing: reading UNIT 1's AST-level pattern (identifier -> concat -> execute) and *reasoning*; reading UNIT 2 and correctly *acquitting* it (`?` placeholder = parameterized = safe). About 1,350 prompt + 220 completion tokens — the only paid step so far.

---

## Slide 10 — Step 9: Evidence validation — the LLM is NOT trusted (`analysis/evidence_validator.py`)

The verdict is a *claim*. The validator turns claims into *facts* by re-reading the real `bank.py` from disk:

**Evidence 1 — `bank.py`, line 19:**

| # | Check (implemented) | Result |
|---|---|---|
| 1 | File exists? (`repo / cited_path`) | ✅ `bank.py` found |
| 2 | Line in range? (1 <= 19 <= total lines) | ✅ file has 100 lines |
| 3 | Cited code literally in that line? (whitespace-normalized `in` comparison) | ✅ matches line 19 exactly |
| → | **VALID — "verified against repository"** | ✅ |

**Evidence 2 — `bank.py`, line 20:** all three checks → ✅ VALID.

### What happens when the model fabricates (the whole point of the project):

| LLM claims | Validator | Reason recorded |
|---|---|---|
| `file: auth/login.py` | ❌ REJECTED | "file does not exist in repository" |
| `line: 450` | ❌ REJECTED | "line 450 out of range (file has 100 lines)" |
| `code: cursor.execute(f"...{user}...")` | ❌ REJECTED | "cited code not found at that line (possible hallucination)" |

**Auto-downgrade gate** (`analysis/analyzer.py`): if a verdict is VULNERABLE but **zero** evidence items survive → status forced to **INCONCLUSIVE** with `[downgraded: no evidence item could be verified against the repository]`. A fabricated bug can never reach the report.

---

## Slide 11 — Step 10: Dedup + RuleResult, then Rule 2 repeats (steps 6-10)

`analysis/deduplicator.py` keys every finding on `(rule_id, file, function, line)` and drops repeats (e.g. if the class chunk and the method chunk cite the same line).

**Rule 1 result:**
```
RuleResult(SQL-001 [HIGH] SQL Injection, VULNERABLE, confidence 0.93,
  evidence: bank.py:19 VALID, bank.py:20 VALID,
  retrieved: 8 units with scores)
```

**Rule 2 (CMD-001) — same machine, new query:**
- Step 6: embed CMD-001 rule → new 384-dim vector
- Step 7: cosine vs the same 15 chunks → top-8: `run_backup_vulnerable` **0.63** 🎯, `run_backup_safe` 0.56, `ping_host_safe` 0.49, ...
- Step 8: one LLM call →
```json
{ "status": "VULNERABLE", "confidence": 0.95,
  "evidence": [
    { "file": "bank.py", "line": 33, "function": "run_backup_vulnerable",
      "code": "cmd = \"tar czf backup.tar.gz \" + filename",
      "reason": "user input concatenated into shell command" },
    { "file": "bank.py", "line": 34, "function": "run_backup_vulnerable",
      "code": "subprocess.run(cmd, shell=True)",
      "reason": "executed with shell=True enables command chaining" } ] }
```
- Step 9: line 33 ✅ / line 34 ✅ → both VALID · Step 10: no dups →
```
RuleResult(CMD-001 [CRITICAL] Command Injection, VULNERABLE, confidence 0.95,
  evidence: bank.py:33 VALID, bank.py:34 VALID)
```

**2 rules = exactly 2 LLM calls.** A 500-rule run is 500 calls — the bill is countable before you start.

---

## Slide 12 — The Final Report (`app.py` renders `AnalysisResult`)

```
🔍 AI Security RAG Analyzer — Verified Report

🔴 SQL-001 [HIGH]     SQL Injection      → VULNERABLE (confidence 0.93)
   bank.py:19  find_user_vulnerable  ✔ verified against repository
   bank.py:20  find_user_vulnerable  ✔ verified against repository

🔴 CMD-001 [CRITICAL] Command Injection  → VULNERABLE (confidence 0.95)
   bank.py:33  run_backup_vulnerable ✔ verified against repository
   bank.py:34  run_backup_vulnerable ✔ verified against repository

📊 1 file · 15 chunks · 2 rules · 2 retrievals · 2 LLM calls
   ~2,700 prompt / ~440 completion tokens · ~11 seconds
```

**Result vs ground truth: 2/2 bugs found · 0 false positives · 4/4 citations verified.**

---

## Slide 13 — The Whole Journey on One Slide

```
 PHASE A — ONCE, LOCAL, $0                    PHASE B — PER RULE, PAID
 ─────────────────────────                    ─────────────────────────
 bank.py (100 lines)                          rules.json (2 rules)
      │                                            │
 [1] file_discovery: find bank.py                  │
 [2] language_detector: ".py" → python             │
 [3] tree_sitter_parser: AST [1-100]               │
       └── function/class nodes = boundaries       │
 [4] semantic_chunker: 15 CodeUnits                │
       └── find_user_vulnerable [15-21]            │
       └── run_backup_vulnerable [31-35]           │
 [5] embedder: 384-dim each ──> chroma_store       │
       (Chroma collection on disk)                 │
             │                                     │
             │         FOR EACH RULE (SQL-001, CMD-001):
             │         [6] retriever: embed rule ──┘
             │         [7] cosine vs 15 chunks → TOP-8 (candidates!)
             │         [8] prompts.py builds 1 call → openrouter_client
             │              → strict JSON {status, confidence, evidence}
             │         [9] evidence_validator vs real file:
             │              file exists? line in range? code exact?
             │              zero valid evidence ⇒ INCONCLUSIVE
             │        [10] deduplicator → RuleResult
             ▼                                     ▼
                    📄 VERIFIED REPORT (Slide 12)
```

## Slide 14 — Why This Matters (5 takeaways)

1. **The LLM never sees "the whole codebase" — and never needs to.** It judges 8 focused functions per rule. 100 lines or 100,000 lines: still 8. Cost and latency are flat.
2. **The AST does the heavy lifting, for free.** Tree-sitter knows that line 15–21 is one named unit — so chunks are real functions, not arbitrary line slices, which is why the verdict can cite meaningful `function:` names.
3. **1 rule = exactly 1 LLM call.** Retrieval, embedding, validation, dedup are all local and cost $0. A 500-rule audit = 500 calls — predictable by construction.
4. **Every 🔴 survives a disk-level fact check.** Fabricated file/line/code is rejected; an unproven VULNERABLE auto-downgrades to INCONCLUSIVE. No hallucinated finding can ship.
5. **Safe twins were retrieved and acquitted.** `find_user_safe` and `run_backup_safe` ranked #2 for their rules — and the model correctly cleared them. Zero false positives is a feature, not luck.

> **Q&A one-liner:** *"Embeddings decide where to look, the LLM decides what it means, and the validator decides what we're allowed to claim."*

---
*Module names in this deck match the actual project (`ingestion/`, `embeddings/`, `vector_store/`, `retrieval/`, `llm/`, `analysis/`). Similarity scores and token counts are realistic illustrative values; structure, order, and file/line references are exact.*





