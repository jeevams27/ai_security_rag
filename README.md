# 🎓 Live Walkthrough: 100 Lines of Code + 2 Security Rules
### How the Verified RAG Security Analyzer works — end to end, every stage, real numbers

---

## Slide 1 — The Two Inputs (nothing else is needed)

### Input A: `bank.py` — exactly 100 lines, containing 2 hidden bugs

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

### Input B: `rules.json` — the 2 security rules (pure input data, nothing hardcoded)

```json
[
  { "rule_id": "SQL-001", "severity": "HIGH", "category": "SQL Injection",
    "requirement": "User-controlled input must not be concatenated directly into SQL queries." },
  { "rule_id": "CMD-001", "severity": "CRITICAL", "category": "Command Injection",
    "requirement": "User-controlled input must not be passed directly into operating-system command execution." }
]
```

**Ground truth (what a human auditor knows):** line 19 violates SQL-001, lines 33-34 violate CMD-001. Everything else is safe. The analyzer must find exactly this — with proof.

---

## Slide 2 — PHASE A: Indexing (once, local, FREE, no LLM)

### Stage 1 — File discovery (`ingestion/file_discovery.py`)

Walks the folder, finds `bank.py`. Skips `node_modules`, `.git`, files over 1 MB, binaries.
Result: **1 file accepted.**

### Stage 2 — Language detection (`ingestion/language_detector.py`)

```
bank.py  ->  extension ".py"  ->  EXTENSION_MAP[".py"]  ->  "python"
```

This picks which Tree-sitter **grammar** will parse the file. (Unsupported extension = file skipped + warning shown in the UI.)

### Stage 3 — Tree-sitter parsing (`ingestion/tree_sitter_parser.py`)

The Python grammar builds a real syntax tree:

```
module                                    [lines 1-100]
  expression_statement  (docstring)       [line 1]
  import_statement      (import os)       [line 2]
  import_statement      (import sqlite3)  [line 3]
  function_definition   (get_db)                [10-12]   <- chunk!
  function_definition   (find_user_vulnerable)  [15-21]   <- chunk!
  function_definition   (find_user_safe)        [24-28]   <- chunk!
  function_definition   (run_backup_vulnerable) [31-35]   <- chunk!
  ...
  class_definition      (Account)         [56-71]         <- chunk!
    function_definition (__init__)        [57-59]         <- chunk!
    function_definition (deposit)         [61-65]         <- chunk!
    function_definition (withdraw)        [67-71]         <- chunk!
```

### Stage 4 — Semantic chunking (`ingestion/semantic_chunker.py`)

The chunker cuts the tree at every function/class boundary. **100 lines become 15 chunks:**

| # | Chunk (symbol) | Type | Lines |
|---|---|---|---|
| 1 | `get_db` | function | 10-12 |
| 2 | `find_user_vulnerable` | function | 15-21 |
| 3 | `find_user_safe` | function | 24-28 |
| 4 | `run_backup_vulnerable` | function | 31-35 |
| 5 | `run_backup_safe` | function | 38-42 |
| 6 | `read_statement` | function | 45-48 |
| 7 | `hash_pin` | function | 51-53 |
| 8 | `Account` | class | 56-71 |
| 9 | `Account.__init__` | method | 57-59 |
| 10 | `Account.deposit` | method | 61-65 |
| 11 | `Account.withdraw` | method | 67-71 |
| 12 | `monthly_report` | function | 74-78 |
| 13 | `ping_host_safe` | function | 81-85 |
| 14 | `export_users_vulnerable` | function | 88-95 |
| 15 | `greet` | function | 98-99 |

**Why chunks, not raw lines?** The LLM will see *complete functions* — full context, never half a sentence. Each chunk becomes one `CodeUnit`: `{file, language, symbol, type, start_line, end_line, code, sha1 id}`.

### Stage 5 — Embedding + Vector DB (`embeddings/` then `vector_store/`)

Each chunk is wrapped with a metadata header, then embedded:

```
file: bank.py
language: python
function: find_user_vulnerable
def find_user_vulnerable(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    ...
        |
        v   all-MiniLM-L6-v2 (runs LOCALLY, free)
[0.018, -0.221, 0.442, 0.095, ... 380 more numbers ...]   <- 384-dim vector
```

All 15 vectors stored in **ChromaDB** on disk. Indexing complete.

> 💰 **Cost so far: $0.00 · LLM calls: 0 · time: about 2 seconds**

---

## Slide 3 — PHASE B, Rule 1 of 2: SQL-001 (the full journey)

### Step 6 — The rule becomes a vector too (`retrieval/retriever.py`)

The rule is rendered as text and embedded with the SAME model (rule and code must live in the same meaning-space):

```
Security category: SQL Injection
Severity: HIGH
Requirement: User-controlled input must not be concatenated directly into SQL queries.
        |
        v   same embedder
[0.131, 0.204, -0.087, ...]   <- the rule's barcode
```

### Step 7 — Top-K retrieval from ChromaDB

ChromaDB compares the rule vector against all 15 chunk vectors. Top 8 returned:

| Rank | Chunk | Lines | Similarity | Contains the bug? |
|---|---|---|---|---|
| 1 | `find_user_vulnerable` | 15-21 | **0.61** | 🎯 YES (line 19) |
| 2 | `find_user_safe` | 24-28 | 0.55 | no - safe version |
| 3 | `export_users_vulnerable` | 88-95 | 0.48 | no - SQL but no user input |
| 4 | `get_db` | 10-12 | 0.41 | no - just opens DB |
| 5 | `read_statement` | 45-48 | 0.33 | no |
| 6 | `run_backup_vulnerable` | 31-35 | 0.31 | no (different bug!) |
| 7 | `hash_pin` | 51-53 | 0.27 | no |
| 8 | `monthly_report` | 74-78 | 0.22 | no |

⚠️ **Key teaching point:** the buggy function AND the safe function are both retrieved. Similarity is not guilt — retrieval only says "the answer is probably in these 8." Judging comes next.

### Step 8 — The ONE LLM call for this rule (`llm/prompts.py` + OpenRouter)

The actual prompt sent (abridged — real one includes all 8 full code units):

```
SYSTEM: You are a security-analysis reasoning engine.
STRICT RULES:
- Analyze ONLY the supplied code. Do not invent source code.
- Do not invent files. Do not invent line numbers. Do not invent functions.
- Semantic similarity is NOT proof of a vulnerability.
- Every piece of evidence MUST copy the exact file, line, and snippet.
- Respond with STRICT JSON ONLY: {status, confidence, reason, evidence[]}

USER:  SECURITY RULE: id: SQL-001, severity: HIGH, category: SQL Injection
       requirement: User-controlled input must not be concatenated directly
       into SQL queries.
       RETRIEVED CODE UNITS (8):
       --- UNIT 1 --- file: bank.py, function: find_user_vulnerable,
           lines: 15-21, similarity: 0.61
           code: <full function text>
       --- UNIT 2 --- ... (7 more)
```

Typical model response (temperature 0.0, deterministic):

```json
{
  "status": "VULNERABLE",
  "confidence": 0.93,
  "reason": "In find_user_vulnerable, the 'username' parameter is concatenated directly into the SQL string on line 19 and executed on line 20. The neighboring find_user_safe shows the safe parameterized form, confirming no sanitization is applied in the vulnerable variant.",
  "evidence": [
    { "file": "bank.py", "line": 19, "function": "find_user_vulnerable",
      "code": "query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"",
      "reason": "user-controlled 'username' concatenated into SQL" },
    { "file": "bank.py", "line": 20, "function": "find_user_vulnerable",
      "code": "cur.execute(query)",
      "reason": "the tainted query is executed" }
  ]
}
```

Token meter: about 1,350 prompt tokens + 220 completion tokens. **This is the only paid step.**

### Step 9 — Evidence validation: the LLM is NOT trusted (`analysis/evidence_validator.py`)

Every evidence item is re-checked against the real `bank.py` on disk:

**Evidence item 1 — `bank.py`, line 19:**

| Check | Result |
|---|---|
| 1. File exists? | ✅ `bank.py` found in the uploaded repo |
| 2. Line 19 in range? | ✅ file has 100 lines |
| 3. Exact code in file? | ✅ whitespace-normalized match: `query = "SELECT * FROM users WHERE name = '" + username + "'"` is literally line 19 |
| → Verdict | ✅ **VALID — "verified against repository"** |

**Evidence item 2 — `bank.py`, line 20:** same three checks → ✅ VALID.

**What if the LLM had lied?** (three failure demos)

| LLM claims | Validator says | Why |
|---|---|---|
| `file: auth/login.py` | ❌ rejected | "file 'auth/login.py' does not exist" |
| `line: 450` | ❌ rejected | "line 450 out of range (file has 100 lines)" |
| `code: cursor.execute(f"...{user}...")` | ❌ rejected | "cited code not found in file (possible fabrication)" |

And the final gate in `analyzer.py`: if ALL evidence had failed, the VULNERABLE verdict would be **downgraded to INCONCLUSIVE** with the annotation `[downgraded: no evidence item could be verified against the repository]`.

### Step 10 — Deduplication + RuleResult (`analysis/deduplicator.py`)

Findings keyed by `(rule_id, file, function, line)` — duplicates removed. Final result for rule 1:

```
RuleResult(
  rule=SQL-001 [HIGH] SQL Injection,
  status=VULNERABLE,  confidence=0.93,
  evidence=[bank.py:19 ✔ verified, bank.py:20 ✔ verified],
  retrieved=[8 units with scores]
)
```

---

## Slide 4 — PHASE B, Rule 2 of 2: CMD-001 (same pipeline, new rule)

Nothing is reused except the index — the rule changes, the journey repeats:

**Retrieval** (new rule vector → different top-8):

| Rank | Chunk | Lines | Similarity | Contains the bug? |
|---|---|---|---|---|
| 1 | `run_backup_vulnerable` | 31-35 | **0.63** | 🎯 YES (lines 33-34) |
| 2 | `run_backup_safe` | 38-42 | 0.56 | no - validates + no shell |
| 3 | `ping_host_safe` | 81-85 | 0.49 | no - allow-list |
| 4 | `find_user_vulnerable` | 15-21 | 0.28 | no |
| ... | (4 more) | | < 0.25 | no |

**LLM verdict:**

```json
{ "status": "VULNERABLE", "confidence": 0.95,
  "reason": "run_backup_vulnerable concatenates 'filename' into a shell command and runs it with shell=True (lines 33-34). An attacker passing 'x; rm -rf /' would execute arbitrary commands.",
  "evidence": [
    { "file": "bank.py", "line": 33, "function": "run_backup_vulnerable",
      "code": "cmd = \"tar czf backup.tar.gz \" + filename",
      "reason": "user input concatenated into shell command" },
    { "file": "bank.py", "line": 34, "function": "run_backup_vulnerable",
      "code": "subprocess.run(cmd, shell=True)",
      "reason": "command executed with shell=True" } ] }
```

**Validation:** line 33 ✅ in file, in range, code matches · line 34 ✅ · → both VALID.
**Dedup:** no duplicates. → `RuleResult(CMD-001, VULNERABLE, 0.95, 2 verified evidence items)`.

---

## Slide 5 — The Final Report (what the UI shows)

```
🔍 AI Security RAG Analyzer — Report

🔴 SQL-001 [HIGH]     SQL Injection      →  VULNERABLE (confidence 0.93)
   Evidence: bank.py:19 ✔ verified against repository
             bank.py:20 ✔ verified against repository

🔴 CMD-001 [CRITICAL] Command Injection  →  VULNERABLE (confidence 0.95)
   Evidence: bank.py:33 ✔ verified against repository
             bank.py:34 ✔ verified against repository

📊 Metrics: 2 rules · 2 retrievals · 2 LLM calls
            ~2,700 prompt tokens · ~440 completion tokens · ~11 seconds
```

Matches ground truth exactly: **2/2 bugs found, 0 false alarms, every citation verified.**

---

## Slide 6 — The Whole Journey on One Slide

```
 bank.py (100 lines)          rules.json (2 rules)
        |                           |
        v                           |
 [1] discover files                 |
 [2] detect language (.py)          |
 [3] Tree-sitter parse              |
 [4] 15 semantic chunks             |
 [5] embed locally -> ChromaDB      |
        |                           |
        |      FOR EACH RULE:       v
        |        [6] embed rule text
        |        [7] top-8 retrieval (candidates only!)
        |        [8] ONE LLM call (strict JSON contract)
        |        [9] validate every citation vs real file
        |            file exists? line in range? code exact?
        |       [10] dedupe + downgrade VULNERABLE if unproven
        v                           v
            VERIFIED REPORT (with metrics)
```

## Slide 7 — Why the Audience Should Care (takeaways)

1. **The LLM never saw all 100 lines at once** — it judged only 8 focused chunks per rule. At 100,000 lines it would still see just 8 per rule. Cost is flat.
2. **2 rules = exactly 2 LLM calls.** Predictable bill, no agent loops.
3. **Every 🔴 has receipts.** Each claim survived a disk-level fact check; a fabricated file, line, or snippet would have been rejected, and an unproven VULNERABLE auto-downgrades to INCONCLUSIVE.
4. **Safe code was retrieved too — and correctly acquitted.** `find_user_safe` and `run_backup_safe` appear in the top-8 for both rules, and the LLM cleared them. That is why there are zero false positives.
5. **Everything else is free and local.** Embeddings, vector search, validation, dedup — $0. Only the judging step calls the paid API.

> One-liner for Q&A: **"Embeddings decide where to look, the LLM decides what it means, and the validator decides what we're allowed to claim."**




