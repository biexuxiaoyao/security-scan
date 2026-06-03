"""Multi-model AI provider adapter — OpenAI, Azure OpenAI, Ollama, etc."""

from __future__ import annotations

import os
from typing import Any


class AIProvider:
    """Unified interface for different LLM backends.

    Supports OpenAI, Azure OpenAI, and any OpenAI-compatible API
    (Ollama, DeepSeek, vLLM, etc.) via the ``base_url`` config.

    The actual OpenAI SDK import is deferred — the module is a no-op
    when ``openai`` is not installed (the caller should check
    ``available`` first).
    """

    def __init__(self, config: dict):
        self.config = config.get("ai", {})
        self._client: Any = None

    # ── properties ────────────────────────────────────────────

    @property
    def available(self) -> bool:
        """Return True if the ``openai`` SDK is installed."""
        try:
            import openai  # noqa: F401
            return True
        except ImportError:
            return False

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

    # ── client ────────────────────────────────────────────────

    def _get_client(self) -> Any:
        """Lazy-init the OpenAI client."""
        if self._client is None:
            import openai
            self._client = openai.OpenAI(
                api_key=self.api_key or "sk-placeholder",
                base_url=self.base_url,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
        return self._client

    # ── classification ────────────────────────────────────────

    def classify(self, messages: list[dict[str, str]]) -> dict:
        """Send a single classification prompt to the LLM.

        Parameters
        ----------
        messages :
            Chat messages from ``PromptBuilder.build()``.

        Returns
        -------
        dict
            Raw API response dict with keys ``choices``, ``usage``, etc.
        """
        if not self.available:
            raise RuntimeError("openai SDK not installed (pip install security-scan[ai])")

        client = self._get_client()
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore
            temperature=0.0,
            max_tokens=256,
        )
        return response

    def classify_batch(
        self, prompts: list[list[dict[str, str]]]
    ) -> list[dict]:
        """Send multiple classification prompts (sequential or parallel).

        Currently sequential; parallel execution is reserved for future.

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
                text = response.choices[0].message.content or ""
                verdict = parser.parse_response(text)
            except Exception as exc:
                verdict = {"is_sensitive": True, "confidence": 0.5, "reason": f"API error: {exc}"}
            results.append(verdict)
        return results
