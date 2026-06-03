"""Multi-model AI provider adapter — OpenAI, Azure OpenAI, Ollama, etc."""


class AIProvider:
    """Unified interface for different LLM backends."""

    def __init__(self, config: dict):
        self.config = config

    def classify_batch(self, prompts: list[str]) -> list[dict]:
        """Send batch of prompts to the configured LLM and return results."""
        ...
