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
