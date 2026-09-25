# Application Security Testing — Notes

Study notes on application security testing approaches (SAST/DAST), the SAST
tool landscape, and how detection engines work under the hood — from rule-based
patterns to AI-native models.

## SAST vs DAST

- **SAST** — Static Application Security Testing: analyzes the **source code**
  without running the application.
- **DAST** — Dynamic Application Security Testing: tests **while the
  application is running**.

Both are critical approaches to application security testing.

**Shared disadvantage:** false positives — the scanner flags safe code as
vulnerable.

## SAST Tool Comparison

| # | Tool | Approach | Languages |
|---|------|----------|-----------|
| 1 | CodeAnt AI | AI-native | 30+ |
| 2 | Snyk Code | AI-assisted | 20+ |
| 3 | Checkmarx One | AI-assisted | 30+ |
| 4 | SonarQube | Rule-based | 30+ |
| 5 | Semgrep | AI-assisted | 30+ |
| 6 | Veracode | AI-assisted | 100+ |

> Semgrep is itself a SAST tool — it analyzes source code statically.

## Detection Models

### 1. Rule-Based Model (Checkmarx / SonarQube)

**How it works:** AST + data-flow graph patterns.

**Basic logic:** a hardcoded pattern (e.g. eval($input)) triggers an alert.

**Problem:** creates a high number of false positives — it flags safe code.

### 2. AI-Assisted (SonarQube AI CodeFix, Checkmarx with AI mapping)

- A **rule-based engine is the primary brain**.
- An **LLM helps to fix the error** (suggested remediation).

### 3. AI-Native Model (CodeRabbit, GraphXio)

**How it works:** tree-sitter structural parsing + a smart AST-based chunking
and retrieval pipeline (RAG).

It does **not** dump 100,000 lines into the model (like an open-net filter
dumping every vulnerability across files, workflows, OWASP, HIPAA, and general
best practices). Instead, it works with constraints on what to look for.

#### How the AST chunking pipeline works

1. **AST chunks** — uses source-code parsers (like **tree-sitter**) to break
   code down into an Abstract Syntax Tree.
2. **Logical grouping** — instead of cutting files into arbitrary text lines,
   it groups code logically by **functions, classes, and blocks**.
3. **Vector storage** — converts the chunks into **vector embeddings** and
   stores them in a **vector database** for retrieval.

## Vulnerability Fingerprints

Vulnerabilities are **digital fingerprints left behind by thousands of past
security issues**. Security researchers mapped them out over the years, and
these fingerprints are what automated tools, SAST scanners, and AI models use
to spot vulnerable code.

The **CVE database** stores reverse-engineered data from past hacks, which
helps tools meet **HIPAA** and **OWASP** standards compliance.

## Open Source Models

- Gemma 4
- DeepSeek V4 Pro
- GLM-5.3
- GPT OSS 120B
- Kimi K2.7 Code
- Kimi K3
- MiniMax M3
- Nemotron 3 Ultra
- Qwen 3.6

## Model Platforms / Gateways

- OpenRouter
- DigitalOcean
- NanoGPT
- LiteLLM
- Vercel AI Gateway
- Portkey
- Cloudflare AI Gateway
- TrueFoundry
- Together AI
- Replicate

## How an LLM Works — 6 Steps

**Text → Tokenization → Embedding → Transformer → Probabilities → Next Token**

1. **Tokenization** — Text is split into tokens and converted into token IDs.
   - Algorithm: BPE / SentencePiece
2. **Embedding** — Token IDs are converted into numerical vectors using an embedding matrix.
   - Algorithm: Embedding lookup
3. **Transformer** — The model understands relationships between tokens using self-attention.
   - Algorithm: `Attention(Q,K,V) = Softmax(QKᵀ / √dₖ)V`
4. **Prediction** — The Transformer produces a score (logit) for every possible next token.
   - Algorithm: Matrix multiplication
5. **Probability** — Logits are converted into probabilities.
   - Algorithm: Softmax
6. **Next Token** — A token is selected and added to the sequence; the process repeats.
   - Algorithm: Greedy / Sampling / Top-K / Top-P decoding

## Inference Parameters


## Vulnerable Flask App — AST Walkthrough

Sample Flask app with three classic vulnerabilities — **SQL injection** (`get_user`),
**command injection** (`ping_host`), and **SSTI** (`/hello`) — followed by its
abstract syntax tree, since AST-based SAST tools scan the tree rather than raw text.

```python
from flask import Flask, request, render_template_string
import sqlite3
import subprocess

app = Flask(__name__)

DATABASE = "users.db"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def get_user(username):
    db = get_db()

    # VULNERABILITY 1: SQL Injection
    query = "SELECT * FROM users WHERE username = '" + username + "'"

    result = db.execute(query)
    user = result.fetchone()

    db.close()
    return user


def ping_host(host):
    # VULNERABILITY 2: Command Injection
    command = "ping -c 1 " + host
    result = subprocess.check_output(
        command,
        shell=True,
        text=True
    )
    return result


@app.route("/user")
def user():
    username = request.args.get("username", "")

    user_data = get_user(username)

    if user_data:
        return {
            "username": user_data["username"],
            "email": user_data["email"]
        }

    return {"error": "User not found"}, 404


@app.route("/ping")
def ping():
    host = request.args.get("host", "")

    result = ping_host(host)

    return {
        "host": host,
        "result": result
    }


@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")

    return render_template_string(
        "<h1>Hello " + name + "</h1>"
    )


if __name__ == "__main__":
    app.run(debug=True)
```

### AST Tree — node / child marked

Legend: `[NODE]` = has children (branch) · `[CHILD]` = terminal leaf (no children)

```text
ast tree  module                                 [NODE - root]
│
├── import_statement                             [NODE]
│   ├── from: flask                              [CHILD]
│   └── imports:                                 [NODE]
│       ├── Flask                                [CHILD]
│       ├── request                              [CHILD]
│       └── render_template_string               [CHILD]
│
├── import_statement                             [NODE]
│   └── sqlite3                                  [CHILD]
│
├── import_statement                             [NODE]
│   └── subprocess                               [CHILD]
│
├── assignment                                   [NODE]
│   ├── name: app                                [CHILD]
│   └── call                                     [NODE]
│       ├── function: Flask                      [CHILD]
│       └── argument: "__name__"                 [CHILD]
│
├── assignment                                   [NODE]
│   ├── name: DATABASE                           [CHILD]
│   └── string: "users.db"                       [CHILD]
│
├── function_definition                          [NODE]
│   ├── name: get_db                             [CHILD]
│   │
│   └── body                                     [NODE]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: conn                       [CHILD]
│       │   └── call                             [NODE]
│       │       ├── object: sqlite3              [CHILD]
│       │       └── function: connect            [CHILD]
│       │       └── argument: DATABASE           [CHILD]
│       │
│       ├── expression_statement                 [NODE]
│       │   └── call                             [NODE]
│       │       ├── object: conn                 [CHILD]
│       │       └── function: row_factory        [CHILD]
│       │
│       └── return_statement                     [NODE]
│           └── identifier: conn                 [CHILD]
│
├── function_definition                          [NODE]
│   ├── name: get_user                           [CHILD]
│   ├── parameter                                [NODE]
│   │   └── username                             [CHILD]
│   │
│   └── body                                     [NODE]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: db                         [CHILD]
│       │   └── call                             [NODE]
│       │       └── get_db()                     [CHILD]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: query                      [CHILD]
│       │   │
│       │   └── binary_operator                  [NODE]
│       │       ├── string                       [NODE]
│       │       │   "SELECT * FROM users WHERE username = '"   [CHILD]
│       │       ├── operator: +                  [CHILD]
│       │       ├── identifier: username         [CHILD]
│       │       ├── operator: +                  [CHILD]
│       │       └── string: "'"                  [CHILD]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: result                     [CHILD]
│       │   └── call                             [NODE]
│       │       ├── object: db                   [CHILD]
│       │       ├── function: execute            [CHILD]
│       │       └── argument: query              [CHILD]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: user                       [CHILD]
│       │   └── call                             [NODE]
│       │       ├── object: result               [CHILD]
│       │       └── function: fetchone           [CHILD]
│       │
│       ├── expression_statement                 [NODE]
│       │   └── call                             [NODE]
│       │       └── db.close()                   [CHILD]
│       │
│       └── return_statement                     [NODE]
│           └── identifier: user                 [CHILD]
│
├── function_definition                          [NODE]
│   ├── name: ping_host                          [CHILD]
│   ├── parameter                                [NODE]
│   │   └── host                                 [CHILD]
│   │
│   └── body                                     [NODE]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: command                    [CHILD]
│       │   └── binary_operator                  [NODE]
│       │       ├── string: "ping -c 1 "         [CHILD]
│       │       ├── operator: +                  [CHILD]
│       │       └── identifier: host             [CHILD]
│       │
│       ├── assignment                           [NODE]
│       │   ├── name: result                     [CHILD]
│       │   └── call                             [NODE]
│       │       ├── function: subprocess.check_output   [CHILD]
│       │       ├── argument: command            [CHILD]
│       │       ├── argument: shell=True         [CHILD]
│       │       └── argument: text=True          [CHILD]
│       │
│       └── return_statement                     [NODE]
│           └── identifier: result               [CHILD]
│
├── decorated_definition                         [NODE]
│   │
│   ├── decorator                                [NODE]
│   │   └── @app.route("/user")                  [CHILD]
│   │
│   └── function_definition                      [NODE]
│       ├── name: user                           [CHILD]
│       │
│       └── body                                 [NODE]
│           │
│           ├── assignment                       [NODE]
│           │   ├── name: username               [CHILD]
│           │   └── call                         [NODE]
│           │       ├── request.args.get         [CHILD]
│           │       └── arguments:               [NODE]
│           │           ├── "username"           [CHILD]
│           │           └── ""                   [CHILD]
│           │
│           ├── assignment                       [NODE]
│           │   ├── name: user_data              [CHILD]
│           │   └── call                         [NODE]
│           │       └── get_user(username)       [CHILD]
│           │
│           ├── if_statement                     [NODE]
│           │   ├── condition: user_data         [CHILD]
│           │   │
│           │   └── consequence                  [NODE]
│           │       └── return_statement         [NODE]
│           │           └── dictionary           [NODE]
│           │               ├── username → user_data["username"]   [CHILD]
│           │               └── email → user_data["email"]         [CHILD]
│           │
│           └── return_statement                 [NODE]
│               └── tuple                        [NODE]
│                   ├── {"error": "User not found"}   [CHILD]
│                   └── 404                      [CHILD]
│
├── decorated_definition                         [NODE]
│   │
│   ├── decorator                                [NODE]
│   │   └── @app.route("/ping")                  [CHILD]
│   │
│   └── function_definition                      [NODE]
│       ├── name: ping                           [CHILD]
│       │
│       └── body                                 [NODE]
│           │
│           ├── assignment                       [NODE]
│           │   ├── name: host                   [CHILD]
│           │   └── call                         [NODE]
│           │       └── request.args.get("host", "")   [CHILD]
│           │
│           ├── assignment                       [NODE]
│           │   ├── name: result                 [CHILD]
│           │   └── call                         [NODE]
│           │       └── ping_host(host)          [CHILD]
│           │
│           └── return_statement                 [NODE]
│               └── dictionary                   [NODE]
│                   ├── host → host              [CHILD]
│                   └── result → result          [CHILD]
│
├── decorated_definition                         [NODE]
│   │
│   ├── decorator                                [NODE]
│   │   └── @app.route("/hello")                 [CHILD]
│   │
│   └── function_definition                      [NODE]
│       ├── name: hello                          [CHILD]
│       │
│       └── body                                 [NODE]
│           │
│           ├── assignment                       [NODE]
│           │   ├── name: name                   [CHILD]
│           │   └── call                         [NODE]
│           │       └── request.args.get("name", "Guest")   [CHILD]
│           │
│           └── return_statement                 [NODE]
│               └── call                         [NODE]
│                   ├── function: render_template_string   [CHILD]
│                   └── argument                 [NODE]
│                       └── binary_operator      [NODE]
│                           ├── "<h1>Hello "     [CHILD]
│                           ├── +                [CHILD]
│                           ├── name             [CHILD]
│                           ├── +                [CHILD]
│                           └── "</h1>"          [CHILD]
│
└── if_statement                                 [NODE]
    ├── condition                                [NODE]
    │   └── __name__ == "__main__"               [CHILD]
    │
    └── consequence                              [NODE]
        └── call                                 [NODE]
            ├── app.run                          [CHILD]
            └── debug=True                       [CHILD]
```
