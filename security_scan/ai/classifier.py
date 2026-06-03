"""AI secondary classifier — confirms or dismisses rule-engine findings via LLM."""


class AIClassifier:
    """Sends candidate findings to an LLM for secondary classification."""

    def classify(self, findings: list[dict]) -> list[dict]:
        """Batch classify findings; returns enriched results with AI verdict."""
        ...
