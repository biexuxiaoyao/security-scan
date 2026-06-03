"""Rule engine — orchestrates built-in rules, custom rules, whitelist, context analysis."""

from __future__ import annotations

from typing import Any

from security_scan.rules.builtin_rules import get_rules_for_scope, match_rule_on_line
from security_scan.rules.custom_rules import CustomRuleLoader
from security_scan.rules.whitelist import WhitelistFilter
from security_scan.rules.context_analyzer import ContextAnalyzer


class RuleEngine:
    """Combines built-in + custom rules, applies context analysis and whitelist filtering."""

    def __init__(self, config: dict, project_path: str | None = None):
        self.config = config
        self.project_path = project_path
        self.whitelist = WhitelistFilter(config)
        self.context_analyzer = ContextAnalyzer(config)
        self.custom_loader = CustomRuleLoader(config)
        self.encrypted_prefixes = config.get("encrypted_prefixes", [])
        self._all_rules: list[dict[str, Any]] | None = None

    @property
    def all_rules(self) -> list[dict[str, Any]]:
        if self._all_rules is None:
            self._all_rules = self._build_rule_set()
        return self._all_rules

    def _build_rule_set(self) -> list[dict[str, Any]]:
        """Merge built-in rules (all scopes) with custom rules."""
        rules = list(get_rules_for_scope("all"))
        # also collect scope-specific rules — we will filter at match time
        rules.extend(get_rules_for_scope("java"))
        rules.extend(get_rules_for_scope("config"))
        rules.extend(self.custom_loader.load())
        # deduplicate by id
        seen: set[str] = set()
        deduped = []
        for r in rules:
            if r["id"] not in seen:
                seen.add(r["id"])
                deduped.append(r)
        return deduped

    def scan_line(self, line: str, line_number: int, file_scope: str) -> list[dict]:
        """Scan a single line of text with all applicable rules.

        Parameters
        ----------
        line : str
            The text line to scan.
        line_number : int
            1-based line number.
        file_scope : str
            File type scope (``"java"``, ``"properties"``, ``"yaml"``, etc.).

        Returns
        -------
        list[dict]
            Findings from this line (may be empty).
        """
        # ── inline ignore comment → skip entirely ───────────────
        if self.whitelist.has_inline_ignore(line):
            return []

        findings: list[dict] = []
        for rule in get_rules_for_scope(file_scope):
            finding = match_rule_on_line(rule, line, line_number)
            if finding:
                # ── encrypted prefix check ────────────────────────
                if self._is_encrypted_value(finding):
                    finding["encrypted"] = True
                    finding["severity"] = "LOW"
                    finding["confidence"] = 0.0
                findings.append(finding)
        return findings

    def _is_encrypted_value(self, finding: dict) -> bool:
        """Return True if the matched value starts with a configured encrypted prefix."""
        if not self.encrypted_prefixes:
            return False
        content = finding.get("matched_content", "")
        # Use first occurrence of = or : as separator (avoids picking up
        # base64 padding characters or colons in URLs).
        eq_idx = content.find("=") if "=" in content else -1
        colon_idx = content.find(":") if ":" in content else -1
        if eq_idx >= 0 and (colon_idx < 0 or eq_idx < colon_idx):
            value_part = content[eq_idx + 1:]
        elif colon_idx >= 0:
            value_part = content[colon_idx + 1:]
        else:
            value_part = content
        value_part = value_part.strip().strip("\"'")
        for prefix in self.encrypted_prefixes:
            if value_part.startswith(prefix):
                finding["encrypted_prefix_matched"] = prefix
                return True
        return False

    def post_process(self, findings: list[dict], project_path: str | None = None) -> list[dict]:
        """Apply whitelist filtering and context analysis to all findings.

        Parameters
        ----------
        findings :
            Raw findings from the scanners.
        project_path :
            Project root path, used to locate project-level whitelist file.
            Falls back to ``self.project_path`` if not provided.

        Returns filtered list.
        """
        resolved_path = project_path or self.project_path
        if resolved_path:
            self.whitelist.configure(resolved_path)

        # 1. Context analysis adjusts confidence / severity
        for f in findings:
            self.context_analyzer.analyze(f)

        # 2. Whitelist removes false positives
        findings = self.whitelist.filter(findings)

        # 3. Remove findings below confidence threshold
        min_conf = self.config.get("severity", {}).get("min_confidence_to_report", 0.50)
        findings = [f for f in findings if f.get("confidence", 1.0) >= min_conf]

        return findings
