"""Batch processor — splits large finding lists into API-sized batches."""

from __future__ import annotations

from typing import Any

from security_scan.ai.provider import AIProvider
from security_scan.ai.prompt_builder import PromptBuilder


class BatchProcessor:
    """Manages batching, retries, and fallback for AI classification.

    Design (per 2.7.2 / 2.7.6):
      - LLM is called only on rule-engine candidates (not raw code).
      - If the LLM is unavailable the system degrades gracefully
        (findings keep their original rule-engine verdict).
      - Confidence threshold controls whether AI verdict overrides the
        rule-engine score.
    """

    def __init__(self, config: dict):
        self.config = config
        self.ai_config = config.get("ai", {})
        self.provider = AIProvider(config)
        self.prompt_builder = PromptBuilder()

        self.batch_size = int(self.ai_config.get("batch_size", 20))
        self.confidence_threshold = float(self.ai_config.get("confidence_threshold", 0.7))
        self.fallback_on_error = self.ai_config.get("fallback_on_error", "keep_original")

    # ── public API ────────────────────────────────────────────

    def process(
        self,
        findings: list[dict],
        source_lines_map: dict[str, list[str]] | None = None,
    ) -> list[dict]:
        """Classify findings with LLM, merging verdicts into each finding.

        Parameters
        ----------
        findings :
            Candidate findings from the rule engine (after post_process).
        source_lines_map :
            Optional mapping of file_path → list of source lines, for
            context extraction.

        Returns
        -------
        list[dict]
            Findings enriched with AI verdict fields.
        """
        if not self.provider.enabled or not self.provider.available:
            return self._noop_fallback(findings)

        # Build prompts for all findings
        prompts = self.prompt_builder.build_batch(findings, source_lines_map)

        # Process in batches
        all_verdicts: list[dict] = []
        for i in range(0, len(prompts), self.batch_size):
            batch_prompts = prompts[i : i + self.batch_size]
            batch_verdicts = self.provider.classify_batch(batch_prompts)
            all_verdicts.extend(batch_verdicts)

        # Merge verdicts into findings
        for finding, verdict in zip(findings, all_verdicts):
            self._merge_verdict(finding, verdict)

        return findings

    # ── internals ─────────────────────────────────────────────

    def _merge_verdict(self, finding: dict, verdict: dict[str, Any]) -> None:
        """Merge an AI verdict into a finding (in-place)."""
        is_sensitive = verdict.get("is_sensitive", True)
        ai_confidence = float(verdict.get("confidence", 0.5))
        reason = verdict.get("reason", "")

        finding["ai_verdict"] = is_sensitive
        finding["ai_confidence"] = ai_confidence
        finding["ai_reason"] = reason

        # Override rule-engine values if AI confidence exceeds threshold
        if ai_confidence >= self.confidence_threshold:
            if not is_sensitive:
                # AI says false positive
                finding["confidence"] = min(finding.get("confidence", 0.5), 0.1)
                finding["severity"] = self._demote(finding.get("severity", "LOW"), 2)
                finding["ai_dismissed"] = True
            else:
                # AI confirms — boost confidence
                finding["confidence"] = max(finding.get("confidence", 0.5), 0.9)
                finding["ai_confirmed"] = True

    def _noop_fallback(self, findings: list[dict]) -> list[dict]:
        """Handle case where AI is unavailable."""
        for f in findings:
            f["ai_verdict"] = True
            f["ai_confidence"] = 0.0
            f["ai_reason"] = "AI classification unavailable (service disabled or SDK not installed)"
            f["ai_dismissed"] = False
        return findings

    @staticmethod
    def _demote(severity: str, steps: int = 1) -> str:
        levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        try:
            idx = levels.index(severity)
            return levels[min(idx + steps, len(levels) - 1)]
        except ValueError:
            return severity
