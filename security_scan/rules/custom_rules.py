"""Custom rule loader — loads user-defined rules from .security-scan.yml."""

from __future__ import annotations

import re
from typing import Any


class CustomRuleLoader:
    """Loads and validates custom scanning rules from configuration."""

    REQUIRED_KEYS = {"id", "name", "pattern", "severity"}

    def __init__(self, config: dict):
        self.config = config

    def load(self) -> list[dict[str, Any]]:
        """Parse custom rules from configuration.

        Each custom rule must have at minimum:
          - id
          - name
          - pattern  (regex string)
          - severity

        Optional keys:
          - scope    (default "all")
          - description
        """
        raw_rules = self.config.get("custom_rules", [])
        if not isinstance(raw_rules, list):
            return []

        validated: list[dict[str, Any]] = []
        for raw in raw_rules:
            if not isinstance(raw, dict):
                continue
            missing = self.REQUIRED_KEYS - set(raw.keys())
            if missing:
                continue
            try:
                compiled = re.compile(raw["pattern"], re.IGNORECASE)
            except re.error:
                continue

            validated.append({
                "id": raw["id"],
                "name": raw["name"],
                "scope": raw.get("scope", "all"),
                "severity": raw["severity"],
                "description": raw.get("description", ""),
                "pattern": compiled,
                "pattern_raw": raw["pattern"],
            })
        return validated
