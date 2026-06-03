"""Whitelist filter — suppresses false positives based on user-defined rules."""

from __future__ import annotations

import re
from pathlib import Path


class WhitelistFilter:
    """Filters findings against project-level and global whitelist entries.

    Supports three types of whitelist rules:
      1. **Path + line**: ignore a specific file:line combination.
      2. **Path + pattern**: ignore lines in a file matching a regex.
      3. **Global pattern**: ignore any finding whose content matches a regex.

    Whitelist sources (in order):
      - Project-level ``.security-scan-whitelist`` file
      - Inline comment hints ``// security-scan:ignore`` (handled at scan time)
    """

    WHITELIST_FILE = ".security-scan-whitelist"

    def __init__(self, config: dict):
        self.config = config
        self._rules: list[dict] | None = None

    def load_rules(self, project_path: str) -> list[dict]:
        """Load whitelist rules from the project whitelist file.

        File format: one rule per line, blank lines and ``#`` comments ignored.

        Formats:
          path/to/file.java:123          → ignore line 123
          path/to/file.java:             → ignore entire file
          /pattern/                      → ignore any finding matching this regex
        """
        rules: list[dict] = []
        whitelist_path = Path(project_path) / self.WHITELIST_FILE
        if not whitelist_path.is_file():
            return rules

        for line in whitelist_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if line.startswith("/") and line.endswith("/"):
                # Global regex pattern:  /pattern/
                try:
                    rules.append({
                        "type": "pattern",
                        "pattern": re.compile(line[1:-1], re.IGNORECASE),
                    })
                except re.error:
                    continue
            elif ":" in line:
                file_part, _, line_part = line.partition(":")
                if line_part.strip().isdigit():
                    rules.append({
                        "type": "file_line",
                        "file": file_part.strip(),
                        "line": int(line_part.strip()),
                    })
                else:
                    rules.append({
                        "type": "file",
                        "file": file_part.strip(),
                    })
        return rules

    def filter(self, findings: list[dict]) -> list[dict]:
        """Remove findings that match whitelist rules."""
        # Lazy-load rules from the project path if available
        if self._rules is None:
            self._rules = []

        filtered = []
        for finding in findings:
            if self._matches_whitelist(finding):
                continue
            filtered.append(finding)
        return filtered

    def _matches_whitelist(self, finding: dict) -> bool:
        """Check whether a finding matches any loaded whitelist rule."""
        if not self._rules:
            return False
        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number", 0)
        content = finding.get("matched_content", "")

        for rule in self._rules:
            if rule["type"] == "file_line":
                if rule["file"] in file_path and rule["line"] == line_number:
                    return True
            elif rule["type"] == "file":
                if rule["file"] in file_path:
                    return True
            elif rule["type"] == "pattern":
                if rule["pattern"].search(content):
                    return True
        return False
