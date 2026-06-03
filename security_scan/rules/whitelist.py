"""Whitelist filter — suppresses false positives based on user-defined rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml


class WhitelistFilter:
    """Filters findings against project-level and global whitelist entries.

    Supports three types of whitelist rules:
      1. **Path + line**: ignore a specific file:line combination.
      2. **Path**: ignore all findings in a given file path.
      3. **Global pattern**: ignore any finding whose content matches a regex.

    Whitelist sources (in order, higher priority first):
      1. Project-level ``.security-scan-whitelist`` file
      2. Global ``~/.security-scan/whitelist.yml``
      3. Inline comment hints ``// security-scan:ignore`` (handled at scan time)
    """

    WHITELIST_FILE = ".security-scan-whitelist"
    GLOBAL_WHITELIST_DIR = Path.home() / ".security-scan"
    GLOBAL_WHITELIST_PATH = GLOBAL_WHITELIST_DIR / "whitelist.yml"

    COMMENT_IGNORE_PATTERN = re.compile(r"security-scan:\s*ignore")

    def __init__(self, config: dict):
        self.config = config
        self._rules: list[dict] | None = None
        self._project_path: str | None = None

    def configure(self, project_path: str | None = None) -> None:
        """Set the project path (should be called before first ``filter``)."""
        self._project_path = project_path

    # ── loaders ───────────────────────────────────────────────

    def load_rules(self, project_path: str) -> list[dict]:
        """Load whitelist rules from the project whitelist file.

        File format: one rule per line, blank lines and ``#`` comments ignored.

        Formats:
          path/to/file.java:123          -> ignore line 123
          path/to/file.java:             -> ignore entire file
          /pattern/                      -> ignore any finding matching this regex
        """
        rules: list[dict] = []
        whitelist_path = Path(project_path) / self.WHITELIST_FILE
        if whitelist_path.is_file():
            for line in whitelist_path.read_text(encoding="utf-8").splitlines():
                rule = self._parse_line_rule(line)
                if rule:
                    rules.append(rule)
        return rules

    def load_global_rules(self) -> list[dict]:
        """Load whitelist rules from ``~/.security-scan/whitelist.yml``.

        The YAML file supports the same three rule types::

            rules:
              - path: "src/legacy/*.java"       # glob pattern (full file ignore)
              - path: "OldConfig.java"
                line: 42                         # specific line
              - pattern: "test[A-Z]+"            # regex content match
        """
        rules: list[dict] = []
        if not self.GLOBAL_WHITELIST_PATH.is_file():
            return rules

        try:
            data = yaml.safe_load(self.GLOBAL_WHITELIST_PATH.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return rules

        if not isinstance(data, dict):
            return rules

        raw_rules = data.get("rules", [])
        if not isinstance(raw_rules, list):
            return rules

        for raw in raw_rules:
            if isinstance(raw, str):
                rules.append({"type": "file", "file": raw})
            elif isinstance(raw, dict):
                if "pattern" in raw:
                    try:
                        rules.append({
                            "type": "pattern",
                            "pattern": re.compile(raw["pattern"], re.IGNORECASE),
                        })
                    except re.error:
                        continue
                elif "line" in raw:
                    rules.append({
                        "type": "file_line",
                        "file": raw.get("path", ""),
                        "line": int(raw["line"]),
                    })
                else:
                    rules.append({
                        "type": "file",
                        "file": raw.get("path", ""),
                    })
        return rules

    # ── filtering ─────────────────────────────────────────────

    def filter(self, findings: list[dict]) -> list[dict]:
        """Remove findings that match whitelist rules."""
        if self._rules is None:
            self._rules = []
            if self._project_path:
                self._rules.extend(self.load_rules(self._project_path))
            self._rules.extend(self.load_global_rules())

        filtered = []
        for finding in findings:
            if self._matches_whitelist(finding):
                continue
            filtered.append(finding)
        return filtered

    def has_inline_ignore(self, line: str) -> bool:
        """Return True if *line* contains an inline ignore comment."""
        return bool(self.COMMENT_IGNORE_PATTERN.search(line))

    # ── internals ─────────────────────────────────────────────

    @staticmethod
    def _parse_line_rule(line: str) -> dict | None:
        """Parse a single line from the whitelist file into a rule dict."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        if line.startswith("/") and line.endswith("/"):
            try:
                return {"type": "pattern", "pattern": re.compile(line[1:-1], re.IGNORECASE)}
            except re.error:
                return None

        if ":" in line:
            file_part, _, line_part = line.partition(":")
            if line_part.strip().isdigit():
                return {"type": "file_line", "file": file_part.strip(), "line": int(line_part.strip())}
            return {"type": "file", "file": file_part.strip()}

        return {"type": "file", "file": line}

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
