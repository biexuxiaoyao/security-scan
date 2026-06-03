"""Regex scanner — pattern-based scanning for config files and text files."""


class RegexScanner:
    """Applies regex-based rules to non-Java files."""

    def __init__(self, rules: list[dict]):
        self.rules = rules

    def scan(self, file_path: str) -> list[dict]:
        """Scan a single file with regex rules and return findings."""
        ...
