"""Tests for security_scan.output.console."""

from __future__ import annotations

from security_scan.output.console import ConsoleReporter


class TestConsoleReporter:
    def test_report_with_no_findings(self, capsys):
        reporter = ConsoleReporter()
        reporter.report([])
        captured = capsys.readouterr()
        assert "No security issues found" in captured.out

    def test_report_with_findings(self, capsys):
        reporter = ConsoleReporter()
        findings = [
            {
                "file_path": "src/App.java",
                "line_number": 42,
                "rule_id": "test_rule",
                "rule_name": "Test Rule",
                "description": "A test finding",
                "severity": "CRITICAL",
                "confidence": 0.95,
            }
        ]
        reporter.report(findings)
        captured = capsys.readouterr()
        assert "src/App.java:42" in captured.out
        assert "CRITICAL" in captured.out

    def test_summary(self, capsys):
        reporter = ConsoleReporter()
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "LOW"},
        ]
        reporter.summary(findings, elapsed=1.23)
        captured = capsys.readouterr()
        assert "total=3" in captured.err
        assert "critical=1" in captured.err
