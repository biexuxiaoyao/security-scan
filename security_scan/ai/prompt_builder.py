"""Structured prompt builder for AI classifier."""


class PromptBuilder:
    """Builds classification prompts with code context and judgement rules."""

    def build(self, finding: dict) -> str:
        """Construct a structured prompt for the LLM."""
        ...
