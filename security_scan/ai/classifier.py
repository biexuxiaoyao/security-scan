"""AI secondary classifier — confirms or dismisses rule-engine findings via LLM."""

from __future__ import annotations

from security_scan.ai.batch_processor import BatchProcessor
from security_scan.ai.prompt_builder import PromptBuilder
from security_scan.ai.provider import AIProvider


class AIClassifier:
    """Sends candidate findings to an LLM for secondary classification.

    This is the top-level API for the AI module. It wraps
    ``BatchProcessor`` with a simpler interface.

    Usage::

        classifier = AIClassifier(config)
        enriched = classifier.classify(candidates)
    """

    def __init__(self, config: dict):
        self.config = config
        self.provider = AIProvider(config)
        self.prompt_builder = PromptBuilder()
        self.batch_processor = BatchProcessor(config)

    # ── public API ────────────────────────────────────────────

    def classify(
        self,
        findings: list[dict],
        source_lines_map: dict[str, list[str]] | None = None,
    ) -> list[dict]:
        """Batch classify findings; returns enriched results with AI verdict.

        Parameters
        ----------
        findings :
            Candidate findings from the rule engine.
        source_lines_map :
            Optional mapping of file_path → list of source lines,
            for context extraction in prompts.

        Returns
        -------
        list[dict]
            Findings enriched with AI verdict fields (``ai_verdict``,
            ``ai_confidence``, ``ai_reason``, ``ai_confirmed``,
            ``ai_dismissed``).
        """
        return self.batch_processor.process(findings, source_lines_map)

    # ── convenience ───────────────────────────────────────────

    @property
    def available(self) -> bool:
        """Return True if AI provider is configured and SDK is installed."""
        return self.provider.available and self.provider.enabled

    def read_source_lines(self, file_paths: list[str]) -> dict[str, list[str]]:
        """Read source files into a line-map for context extraction.

        Silently skips unreadable files.
        """
        from security_scan.utils.file_utils import read_file_safe

        result: dict[str, list[str]] = {}
        for fp in file_paths:
            try:
                content, _enc, _conf = read_file_safe(fp)
                result[fp] = content.splitlines()
            except (OSError, UnicodeDecodeError):
                continue
        return result
