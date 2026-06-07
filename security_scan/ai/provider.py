"""Multi-model AI provider adapter — sends direct HTTP requests to any
OpenAI-compatible chat completions API (OpenAI, Azure OpenAI, DeepSeek,
Ollama, vLLM, etc.). Uses only stdlib ``urllib`` — no SDK required.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


class AIProvider:
    """Unified interface for different LLM backends via direct HTTP calls.

    Supports any OpenAI-compatible chat completions API by setting
    the ``base_url`` config to the provider's endpoint (e.g.
    ``https://api.openai.com/v1``, ``http://localhost:11434/v1``).
    """

    def __init__(self, config: dict):
        self.config = config.get("ai", {})

    # ── properties ────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """Always True — uses stdlib urllib, no SDK dependency."""
        return True

    @property
    def enabled(self) -> bool:
        """Return True if AI classification is enabled in config."""
        return bool(self.config.get("enabled", False))

    @property
    def model(self) -> str:
        return self.config.get("model", "gpt-4o-mini")

    @property
    def api_key(self) -> str:
        env_var = self.config.get("api_key_env", "SECURITY_SCAN_AI_KEY")
        return os.environ.get(env_var) or self.config.get("api_key", "")

    @property
    def base_url(self) -> str:
        return self.config.get("base_url", "https://api.openai.com/v1")

    @property
    def timeout(self) -> int:
        return int(self.config.get("timeout", 10))

    @property
    def max_retries(self) -> int:
        return int(self.config.get("max_retries", 3))

    # ── API call ──────────────────────────────────────────────

    def classify(self, messages: list[dict[str, str]]) -> dict:
        """Send a single classification prompt to the LLM via direct HTTP.

        Parameters
        ----------
        messages :
            Chat messages from ``PromptBuilder.build()``.

        Returns
        -------
        dict
            Parsed JSON response with keys ``choices``, ``usage``, etc.
        """
        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": 0.0,
            "max_tokens": 256,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
        }
        key = self.api_key
        if key:
            headers["Authorization"] = f"Bearer {key}"

        url = self.base_url.rstrip("/") + "/chat/completions"
        req = urllib.request.Request(url, data=payload, headers=headers, method="POST")

        last_exc: Exception | None = None
        for attempt in range(max(self.max_retries, 1)):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body)
            except (urllib.error.URLError, urllib.error.HTTPError,
                    OSError, json.JSONDecodeError) as exc:
                last_exc = exc
                if attempt + 1 < self.max_retries:
                    import time
                    time.sleep(1.0 * (attempt + 1))

        raise RuntimeError(
            f"AI API call failed after {self.max_retries} retries: {last_exc}"
        )

    def classify_batch(
        self, prompts: list[list[dict[str, str]]]
    ) -> list[dict]:
        """Send multiple classification prompts (sequential).

        Returns
        -------
        list[dict]
            One parsed verdict dict per input prompt.
        """
        from security_scan.ai.prompt_builder import PromptBuilder

        parser = PromptBuilder()
        results: list[dict] = []
        for messages in prompts:
            try:
                response = self.classify(messages)
                text = response["choices"][0]["message"]["content"] or ""
                verdict = parser.parse_response(text)
            except Exception as exc:
                verdict = {"is_sensitive": True, "confidence": 0.5, "reason": f"API error: {exc}"}
            results.append(verdict)
        return results
