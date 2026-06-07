"""Regex scanner — pattern-based scanning for config files and text files."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from security_scan.rules import RuleEngine
from security_scan.utils.file_utils import read_file_safe, is_binary_file


class RegexScanner:
    """Applies regex-based rules to non-Java files.

    Uses the ``RuleEngine`` to match lines against applicable rules.
    """

    def __init__(self, rule_engine: RuleEngine):
        self.rule_engine = rule_engine

    def scan(self, file_path: str, file_scope: str | None = None,
             content: Optional[str] = None) -> list[dict]:
        """Scan a single file with regex rules and return findings.

        Parameters
        ----------
        file_path :
            Absolute or relative path to the file.
        file_scope :
            Scope string (e.g. ``"properties"``, ``"yaml"``).
            If ``None`` it is inferred from the file extension.
        content :
            Pre-read file content.  If provided, the scanner skips
            ``read_file_safe()`` — useful when the caller has already
            read the file (e.g. for a second scan pass).

        Returns
        -------
        list[dict]
            Unfiltered findings from this file.
        """
        path = Path(file_path)
        if not path.is_file() or is_binary_file(file_path):
            return []

        if file_scope is None:
            file_scope = _scope_from_suffix(path.suffix)

        if content is None:
            try:
                content, _enc, _conf = read_file_safe(file_path)
            except (OSError, UnicodeDecodeError):
                return []

        findings: list[dict] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            line_findings = self.rule_engine.scan_line(line, line_number, file_scope)
            for f in line_findings:
                f["file_path"] = str(path)
            findings.extend(line_findings)

        return findings


def _scope_from_suffix(suffix: str) -> str:
    """Map file suffix to a scope name understood by the rule engine."""
    mapping = {
        ".java": "java",
        ".properties": "properties",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".txt": "txt",
        ".md": "md",
    }
    return mapping.get(suffix.lower(), "all")
