"""Environment-driven configuration. No secrets or models are hard-coded."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    # OpenRouter (LLM reasoning layer)
    openrouter_api_key: str = ""
    openrouter_model: str = "openai/gpt-4o-mini"
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    llm_timeout_seconds: int = 120
    llm_temperature: float = 0.0

    # Embeddings (retrieval layer): local sentence-transformers model
    embedding_model: str = "all-MiniLM-L6-v2"

    # Vector store
    chroma_dir: str = ".chroma"
    collection_name: str = "code_units"

    # Retrieval
    top_k: int = 8

    # Chunking guards
    max_unit_chars: int = 6000
    max_file_bytes: int = 1_000_000

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            openrouter_api_key=os.getenv("OPENROUTER_API_KEY", ""),
            openrouter_model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
            openrouter_base_url=os.getenv(
                "OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"
            ),
            llm_timeout_seconds=int(os.getenv("LLM_TIMEOUT_SECONDS", "120")),
            llm_temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
            embedding_model=os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2"),
            chroma_dir=os.getenv("CHROMA_DIR", ".chroma"),
            collection_name=os.getenv("COLLECTION_NAME", "code_units"),
            top_k=int(os.getenv("TOP_K", "8")),
            max_unit_chars=int(os.getenv("MAX_UNIT_CHARS", "6000")),
            max_file_bytes=int(os.getenv("MAX_FILE_BYTES", "1000000")),
        )
