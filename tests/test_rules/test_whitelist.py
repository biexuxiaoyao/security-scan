"""Tests for security_scan.rules.whitelist."""

from __future__ import annotations

from pathlib import Path

from security_scan.rules.whitelist import WhitelistFilter


class TestWhitelistFilter:
    def test_empty_findings_pass_through(self):
        wf = WhitelistFilter({})
        assert wf.filter([]) == []

    def test_no_rules_no_filtering(self):
        wf = WhitelistFilter({})
        findings = [{"file_path": "a.java", "line_number": 1, "matched_content": "pass"}]
        assert wf.filter(findings) == findings

    def test_rule_file_line_removes_finding(self, tmp_path: Path):
        wf = WhitelistFilter({})
        wl = tmp_path / ".security-scan-whitelist"
        wl.write_text("src/Bad.java:42\n")
        wf._rules = wf.load_rules(str(tmp_path))

        findings = [
            {"file_path": "src/Bad.java", "line_number": 42, "matched_content": "x"},
            {"file_path": "src/Good.java", "line_number": 10, "matched_content": "y"},
        ]
        result = wf.filter(findings)
        assert len(result) == 1
        assert result[0]["file_path"] == "src/Good.java"

    def test_global_pattern_rule(self, tmp_path: Path):
        wf = WhitelistFilter({})
        wl = tmp_path / ".security-scan-whitelist"
        wl.write_text("/test_prefix/\n")
        wf._rules = wf.load_rules(str(tmp_path))

        findings = [
            {"file_path": "a.txt", "line_number": 1, "matched_content": "test_prefix_123"},
            {"file_path": "b.txt", "line_number": 2, "matched_content": "real_secret"},
        ]
        result = wf.filter(findings)
        assert len(result) == 1
        assert result[0]["matched_content"] == "real_secret"

    def test_comments_are_ignored(self, tmp_path: Path):
        wf = WhitelistFilter({})
        wl = tmp_path / ".security-scan-whitelist"
        wl.write_text("# this is a comment\nsrc/Foo.java:5\n")
        wf._rules = wf.load_rules(str(tmp_path))
        assert len(wf._rules) == 1
