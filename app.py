"""Streamlit UI for the AI Security RAG Analyzer.

Run:  python -m streamlit run app.py
"""

from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

import streamlit as st

from analysis.analyzer import SecurityAnalyzer
from analysis.evidence_validator import EvidenceValidator
from config import Config
from embeddings.embedder import create_embedder
from ingestion.indexer import Indexer
from json_io import load_rules_bytes, load_rules_file, loads_rules
from models.schemas import SecurityRule
from retrieval.retriever import Retriever
from vector_store.chroma_store import ChromaStore

st.set_page_config(page_title="AI Security RAG Analyzer", layout="wide")
st.title("AI Security RAG Analyzer")
st.caption("Tree-sitter -> semantic code units -> embeddings -> vector DB -> "
           "rule retrieval -> LLM reasoning -> grounded evidence")

config = Config.from_env()

for key, default in {"repo_dir": None, "repo_key": None, "index_stats": None,
                     "report": None, "rules": []}.items():
    st.session_state.setdefault(key, default)

with st.sidebar:
    st.header("Configuration")
    st.write(f"**LLM model:** `{config.openrouter_model}`")
    st.write(f"**Embedding model:** `{config.embedding_model}` (local)")
    top_k = st.number_input("Top-K retrieved units", min_value=1,
                            max_value=50, value=config.top_k)
    chroma_dir = st.text_input("Vector DB directory", value=config.chroma_dir)
    st.write("**OpenRouter key:**",
             "configured" if config.openrouter_api_key else "MISSING")

col1, col2 = st.columns(2)
with col1:
    st.subheader("1. Source code")
    src_method = st.radio(
        "Source input method",
        ["Upload files / ZIP", "Paste code", "Local folder path"],
        horizontal=True, key="src_method")
    src_uploads, paste_name, paste_code, repo_path_text = [], "snippet.py", "", ""
    if src_method == "Upload files / ZIP":
        src_uploads = st.file_uploader(
            "Upload source files (any type, multiple) or a .zip of a folder",
            type=None, accept_multiple_files=True, key="src_uploads")
    elif src_method == "Paste code":
        paste_name = st.text_input(
            "File name (extension sets the language)", value="snippet.py")
        paste_code = st.text_area("Code", height=220)
    else:
        repo_path_text = st.text_input(
            "Local folder path", value=str(Path("benchmark/source").resolve()))
with col2:
    st.subheader("2. Security rules")
    rules_method = st.radio(
        "Rules input method", ["Upload file", "Paste JSON", "Local file path"],
        horizontal=True, key="rules_method")
    rules_upload, rules_paste, rules_path_text = None, "", ""
    if rules_method == "Upload file":
        rules_upload = st.file_uploader(
            "Upload a rules file (JSON array)", type=None, key="rules_upload")
    elif rules_method == "Paste JSON":
        rules_paste = st.text_area(
            "Rules JSON array", height=220,
            placeholder='[{"rule_id": "SQL-001", "severity": "HIGH", '
                        '"category": "SQL Injection", "requirement": "..."}]')
    else:
        rules_path_text = st.text_input(
            "Local rules file path",
            value=str(Path("benchmark/security_rules.json").resolve()))


def load_rules() -> list[SecurityRule]:
    """Load rules from the selected source.

    Accepts an array of rule objects, a single rule object, several
    concatenated arrays, or one object per line (JSONL) -- see json_io.
    """
    if rules_method == "Upload file":
        if rules_upload is None:
            raise ValueError("Upload a rules file first.")
        raw = load_rules_bytes(rules_upload.read())
    elif rules_method == "Paste JSON":
        if not rules_paste.strip():
            raise ValueError("Paste the rules JSON first.")
        raw = loads_rules(rules_paste)
    else:
        raw = load_rules_file(rules_path_text)
    return [SecurityRule.from_dict(item) for item in raw]


def prepare_repo() -> Path:
    if src_method == "Local folder path":
        p = Path(repo_path_text)
        if not p.is_dir():
            raise ValueError(f"Folder not found: {p}")
        return p

    if src_method == "Upload files / ZIP":
        if not src_uploads:
            raise ValueError("Upload at least one source file or a .zip.")
        key = tuple((f.name, f.size) for f in src_uploads)
        if st.session_state.repo_key != key:
            tmp = Path(tempfile.mkdtemp(prefix="rag_repo_"))
            for f in src_uploads:
                if f.name.lower().endswith(".zip"):
                    with zipfile.ZipFile(f) as zf:
                        zf.extractall(tmp)
                else:
                    (tmp / Path(f.name).name).write_bytes(f.getvalue())
            st.session_state.repo_dir = str(tmp)
            st.session_state.repo_key = key
        return Path(st.session_state.repo_dir)

    if not paste_code.strip():
        raise ValueError("Paste some code first.")
    key = ("paste", paste_name, hash(paste_code))
    if st.session_state.repo_key != key:
        tmp = Path(tempfile.mkdtemp(prefix="rag_repo_"))
        name = Path(paste_name).name or "snippet.py"
        (tmp / name).write_text(paste_code, encoding="utf-8")
        st.session_state.repo_dir = str(tmp)
        st.session_state.repo_key = key
    return Path(st.session_state.repo_dir)


build = st.button("Build Index", type="primary")
analyze = st.button("Analyze Security")

if build:
    try:
        repo_dir = prepare_repo()
    except ValueError as exc:
        st.error(str(exc))
        st.stop()
    with st.spinner("Indexing (parse -> units -> embeddings -> vector DB)..."):
        embedder = create_embedder(config)
        store = ChromaStore(persist_dir=chroma_dir,
                            collection_name=config.collection_name)
        indexer = Indexer(embedder, store, max_file_bytes=config.max_file_bytes)
        stats = indexer.index_repository(repo_dir)
    st.session_state.index_stats = stats.to_dict()
    st.success("Index built (unchanged files reused from cache).")

if st.session_state.index_stats:
    from ui_explorer import render_chunks_panel, render_tree_panel

    tab_overview, tab_chunks, tab_tree = st.tabs(
        ["📊 Indexing", "🧩 Code chunks", "🌳 Parse tree"])
    with tab_overview:
        st.subheader("Indexing")
        s = st.session_state.index_stats
        c = st.columns(7)
        c[0].metric("Files", s["files"])
        c[1].metric("Lines", s["lines"])
        c[2].metric("Languages", len(s["languages"]))
        c[3].metric("Code units", s["code_units"])
        c[4].metric("Embeddings", s["embeddings"])
        c[5].metric("Vector records", s["vector_records"])
        c[6].metric("Cached files", s["files_reused_from_cache"])
        st.json(s["languages"])
        if s.get("files_skipped"):
            shown = s.get("skipped_files", [])[:10]
            extra = f" ... and {s['files_skipped'] - len(shown)} more" \
                if s["files_skipped"] > len(shown) else ""
            st.warning(
                f"⚠️ {s['files_skipped']} file(s) were SKIPPED because their "
                f"language is not supported and were NOT analyzed: "
                f"{', '.join(shown)}{extra}")
        if s["files"] == 0:
            st.error(
                "❌ No supported source files were found. Supported languages: "
                "Python (.py), Java (.java), JavaScript (.js/.jsx/.mjs/.cjs), "
                "TypeScript (.ts/.tsx), C (.c/.h), C++ (.cpp/.cc/.cxx/.hpp), "
                "Go (.go). Files of any other type cannot be analyzed.")
    with tab_chunks:
        render_chunks_panel(Path(st.session_state.repo_dir))
    with tab_tree:
        render_tree_panel(Path(st.session_state.repo_dir))

if analyze:
    if not st.session_state.index_stats:
        st.warning("Build the index first.")
        st.stop()
    if not config.openrouter_api_key:
        st.error("OPENROUTER_API_KEY is not configured.")
        st.stop()
    try:
        rules = load_rules()
        repo_dir = prepare_repo()
    except ValueError as exc:
        st.error(str(exc))
        st.stop()

    from llm.openrouter_client import OpenRouterClient

    embedder = create_embedder(config)
    store = ChromaStore(persist_dir=chroma_dir,
                        collection_name=config.collection_name)
    retriever = Retriever(embedder, store)
    llm = OpenRouterClient(
        api_key=config.openrouter_api_key, model=config.openrouter_model,
        base_url=config.openrouter_base_url,
        timeout_seconds=config.llm_timeout_seconds,
        temperature=config.llm_temperature)
    analyzer = SecurityAnalyzer(retriever, llm, EvidenceValidator(repo_dir),
                                top_k=int(top_k))
    with st.spinner(f"Analyzing {len(rules)} rule(s)..."):
        report = analyzer.analyze(rules)
    st.session_state.report = report.to_dict()

if st.session_state.report:
    report = st.session_state.report
    st.subheader("Vulnerability findings")
    vulnerable = [r for r in report["results"] if r["status"] == "VULNERABLE"]
    safe_count = sum(1 for r in report["results"] if r["status"] == "SAFE")
    inconc_count = sum(1 for r in report["results"] if r["status"] == "INCONCLUSIVE")
    st.caption(f"{len(vulnerable)} vulnerable · {safe_count} safe · "
               f"{inconc_count} inconclusive (only vulnerable rules are shown)")

    remediation = {
        "sql": ("Building SQL by joining strings with user input "
                "(\"SELECT ... '\" + username + \"'\").",
                "Use parameterized queries / placeholders "
                "(cursor.execute(\"... WHERE username = ?\", (username,)))."),
        "command": ("Passing user input into os.system / subprocess with "
                    "shell=True or a joined command string.",
                    "Use subprocess with an argument list and shell=False, "
                    "and validate input against an allowlist."),
        "path": ("Joining user-controlled filenames directly into file paths "
                 "and opening them.",
                 "Resolve the real path and verify it stays inside the "
                 "allowed directory before opening."),
        "ssrf": ("Fetching a URL taken straight from user input.",
                 "Allowlist permitted hosts/schemes and block internal "
                 "IP ranges before making the request."),
        "access": ("Trusting a user-supplied id/role to fetch or modify "
                   "objects without an ownership check.",
                   "Authorize every object access server-side against the "
                   "logged-in user (deny by default)."),
        "inject": ("Concatenating untrusted input into an interpreter, "
                   "query, or command.",
                   "Keep data and code separate: parameterized APIs, "
                   "escaping, and input allowlists."),
    }

    def _remediation_for(result):
        text = f"{result['rule_id']} {result['category']}".lower()
        for key, value in remediation.items():
            if key in text:
                return value
        return ("The pattern shown in the vulnerable code above.",
                "Validate all external input and use the safe, "
                "parameterized API for this operation.")

    if not vulnerable:
        st.success("No vulnerabilities detected.")
    for result in vulnerable:
        st.markdown(f"### 🚨 {result['rule_id']} [{result['severity']}] "
                    f"{result['category']} "
                    f"(confidence {result['confidence']:.2f})")
        st.write("**Why vulnerable:**", result["reason"])
        if result["evidence"]:
            st.write("**Where it is vulnerable:**")
            st.dataframe([
                {
                    "file": e["file"],
                    "line": e["line"],
                    "function": e["function"],
                    "vulnerable code": e["code"],
                    "why": e["reason"],
                }
                for e in result["evidence"]
            ])
        else:
            st.warning("The LLM did not cite any concrete code evidence "
                       "for this finding.")
        not_do, do_instead = _remediation_for(result)
        st.error(f"❌ **What NOT to do:** {not_do}")
        st.success(f"✅ **What to do instead:** {do_instead}")
        st.divider()

    st.subheader("Metrics")
    m = report["metrics"]
    cols = st.columns(6)
    cols[0].metric("Rules analyzed", m["rules_analyzed"])
    cols[1].metric("Retrievals", m["retrievals"])
    cols[2].metric("LLM calls", m["llm_calls"])
    cols[3].metric("Prompt tokens", m["prompt_tokens"])
    cols[4].metric("Completion tokens", m["completion_tokens"])
    cols[5].metric("Runtime (s)", round(m["runtime_seconds"], 2))
    st.download_button("Download report (JSON)", json.dumps(report, indent=2),
                       file_name="security_report.json", mime="application/json")
