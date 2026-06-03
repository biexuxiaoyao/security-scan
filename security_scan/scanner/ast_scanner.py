"""AST scanner — uses tree-sitter and javalang for Java source analysis."""

from __future__ import annotations

from pathlib import Path

from security_scan.rules import RuleEngine
from security_scan.utils.file_utils import read_file_safe, is_binary_file


class ASTScanner:
    """Parses Java AST and applies semantic security rules.

    Uses tree-sitter as the primary parser, falling back to javalang.

    .. note::
        The current implementation falls back to line-based regex scanning
        (via ``RuleEngine.scan_line``). Full AST-based semantic analysis
        will be added when tree-sitter grammar bindings are available.
    """

    def __init__(self, config: dict):
        self.config = config

    def scan(self, file_path: str, rule_engine: RuleEngine) -> list[dict]:
        """Scan a single ``.java`` file and return findings.

        Parameters
        ----------
        file_path :
            Path to the Java source file.
        rule_engine :
            Initialized rule engine for matching.

        Returns
        -------
        list[dict]
            Findings from this file.
        """
        path = Path(file_path)
        if not path.is_file() or is_binary_file(file_path):
            return []

        try:
            content, _enc, _conf = read_file_safe(file_path)
        except (OSError, UnicodeDecodeError):
            return []

        # ── attempt tree-sitter parse (future) ─────────────────
        # ast = self._parse_with_tree_sitter(content)
        # if ast is not None:
        #     return self._scan_ast(ast, rule_engine)

        # ── fallback: line-based regex scan ────────────────────
        findings: list[dict] = []
        for line_number, line in enumerate(content.splitlines(), start=1):
            line_findings = rule_engine.scan_line(line, line_number, "java")
            for f in line_findings:
                f["file_path"] = str(path)
            findings.extend(line_findings)

        return findings
