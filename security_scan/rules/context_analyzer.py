"""Context analyzer — AST-level semantic analysis to reduce false positives."""

from __future__ import annotations

import re
from typing import Any

# Patterns that indicate non-sensitive values
_BOOLEAN_LIKE = re.compile(r'^(true|false|yes|no|on|off)$', re.IGNORECASE)
_NUMERIC_LIKE = re.compile(r'^\d+(\.\d+)?$')
_VERSION_LIKE = re.compile(r'^\d+\.\d+\.\d+$')
_URL_LIKE = re.compile(r'^https?://|^localhost|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

# Variable / key names that suggest the value is NOT a secret
_NON_SECRET_KEY_HINTS = {
    "enabled", "debug", "port", "host", "timeout", "retry",
    "max", "min", "size", "limit", "count", "index", "mode",
    "name", "label", "title", "version", "locale", "timezone",
    "format", "pattern", "type", "level", "priority",
}


class ContextAnalyzer:
    """Analyzes code context to distinguish real secrets from non-sensitive values.

    Adjusts ``confidence`` and ``severity`` on findings based on:
      - Variable / key naming conventions
      - Boolean or numeric value types
      - URL or version patterns (likely non-secrets)
    """

    def __init__(self, config: dict):
        self.config = config

    def analyze(self, finding: dict) -> None:
        """Mutate *finding* in-place based on context heuristics."""
        content: str = finding.get("matched_content", "")
        rule_id: str = finding.get("rule_id", "")

        # ── already marked as encrypted → skip ────────────────
        if finding.get("encrypted"):
            return

        # ── extract the value (the part after = or :) ─────────
        value = self._extract_value(content).strip().strip("\"'")

        # ── boolean-like values → likely not a password ───────
        if _BOOLEAN_LIKE.match(value):
            finding["confidence"] = min(finding.get("confidence", 0.85), 0.15)
            finding["severity"] = self._demote(finding.get("severity", "MEDIUM"), 3)
            return

        # ── numeric values → likely not a secret ─────────────
        if _NUMERIC_LIKE.match(value):
            finding["confidence"] = min(finding.get("confidence", 0.85), 0.10)
            finding["severity"] = self._demote(finding.get("severity", "MEDIUM"), 3)
            return

        # ── version strings → not a secret ───────────────────
        if _VERSION_LIKE.match(value):
            finding["confidence"] = min(finding.get("confidence", 0.85), 0.05)
            finding["severity"] = self._demote(finding.get("severity", "MEDIUM"), 3)
            return

        # ── URL / localhost → not a password ─────────────────
        if _URL_LIKE.match(value):
            finding["confidence"] = min(finding.get("confidence", 0.85), 0.10)
            finding["severity"] = self._demote(finding.get("severity", "MEDIUM"), 3)
            return

        # ── key name hints (e.g. "enabled", "port") ──────────
        key_name = self._extract_key_name(content)
        if key_name and key_name.lower() in _NON_SECRET_KEY_HINTS:
            finding["confidence"] = min(finding.get("confidence", 0.85), 0.20)
            finding["severity"] = self._demote(finding.get("severity", "MEDIUM"), 2)
            return

        # ── password-related key + long value → high confidence
        if rule_id in ("java_plaintext_password", "config_credential_key"):
            if len(value) >= 8:
                finding["confidence"] = max(finding.get("confidence", 0.85), 0.90)

    # ── helpers ────────────────────────────────────────────────

    @staticmethod
    def _extract_value(content: str) -> str:
        """Extract the value part after a ``= `` or ``: `` separator.

        Prefers ``= `` over ``: `` to avoid splitting on protocol colons
        (e.g.  ``https://``).
        """
        eq_idx = content.find("=")
        colon_idx = content.find(":")
        # prefer = if present and appears before or near the colon
        if eq_idx >= 0 and (colon_idx < 0 or eq_idx < colon_idx):
            return content[eq_idx + 1:]
        if colon_idx >= 0:
            return content[colon_idx + 1:]
        return content

    @staticmethod
    def _extract_key_name(content: str) -> str:
        """Extract the key / variable name from a line like ``key = value``."""
        idx = min(
            content.find("=") if "=" in content else len(content),
            content.find(":") if ":" in content else len(content),
        )
        key_part = content[:idx] if idx < len(content) else content
        # Take the last word as the key name
        return key_part.strip().split()[-1] if key_part.strip() else ""

    @staticmethod
    def _demote(severity: str, steps: int = 1) -> str:
        """Demote severity by *steps* levels."""
        levels = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        try:
            idx = levels.index(severity)
            new_idx = min(idx + steps, len(levels) - 1)
            return levels[new_idx]
        except ValueError:
            return severity
