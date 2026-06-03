"""Tests for security_scan.output.sarif_report."""

from __future__ import annotations

import json
from pathlib import Path

from security_scan.output.sarif_report import SARIFReportGenerator


class TestSARIFReportGenerator:
    def test_generate_string(self):
        gen = SARIFReportGenerator()
        findings = [{"severity": "CRITICAL", "rule_id": "test_rule", "file_path": "a.java", "line_number": 42, "description": "Found a secret"}]
        report_str = gen.generate_string(findings)
        report = json.loads(report_str)
        assert report["version"] == "2.1.0"
        assert len(report["runs"]) == 1
        assert len(report["runs"][0]["results"]) == 1
        assert report["runs"][0]["results"][0]["ruleId"] == "test_rule"

    def test_generate_file(self, tmp_path: Path):
        gen = SARIFReportGenerator()
        findings = [{"severity": "HIGH", "rule_id": "r2", "file_path": "b.java", "line_number": 10}]
        out = tmp_path / "report.sarif"
        result = gen.generate(findings, str(out))
        assert result == str(out)
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_empty_findings(self):
        gen = SARIFReportGenerator()
        report = json.loads(gen.generate_string([]))
        assert report["runs"][0]["invocations"][0]["executionSuccessful"] is True
        assert report["runs"][0]["results"] == []

    def test_level_mapping(self):
        gen = SARIFReportGenerator()
        findings = [
            {"severity": "CRITICAL", "rule_id": "r1", "file_path": "a.java", "line_number": 1},
            {"severity": "MEDIUM", "rule_id": "r2", "file_path": "b.java", "line_number": 2},
            {"severity": "LOW", "rule_id": "r3", "file_path": "c.java", "line_number": 3},
        ]
        report = json.loads(gen.generate_string(findings))
        results = report["runs"][0]["results"]
        levels = [r["level"] for r in results]
        assert "error" in levels
        assert "warning" in levels
        assert "note" in levels

    def test_rule_dedup(self):
        gen = SARIFReportGenerator()
        findings = [
            {"severity": "CRITICAL", "rule_id": "same_rule", "file_path": "a.java", "line_number": 1},
            {"severity": "HIGH", "rule_id": "same_rule", "file_path": "b.java", "line_number": 2},
        ]
        report = json.loads(gen.generate_string(findings))
        rules = report["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1  # deduplicated
