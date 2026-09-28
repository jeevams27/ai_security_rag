"""Minimal OpenRouter chat-completions client.

Model and key come from configuration (OPENROUTER_API_KEY /
OPENROUTER_MODEL); nothing is hard-coded.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests


@dataclass
class LLMResponse:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model: str = ""


class OpenRouterClient:
    def __init__(self, api_key: str, model: str,
                 base_url: str = "https://openrouter.ai/api/v1",
                 timeout_seconds: int = 120, temperature: float = 0.0) -> None:
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is not configured.")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.temperature = temperature

    def chat(self, messages: list[dict[str, str]]) -> LLMResponse:
        response = requests.post(
            f"{self.base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self.model,
                "messages": messages,
                "temperature": self.temperature,
            },
            timeout=self.timeout_seconds,
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"OpenRouter error {response.status_code}: {response.text[:500]}")
        data = response.json()
        choice = data["choices"][0]["message"]
        usage = data.get("usage", {}) or {}
        return LLMResponse(
            content=choice.get("content", "") or "",
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            total_tokens=int(usage.get("total_tokens", 0)),
            model=data.get("model", self.model),
        )
