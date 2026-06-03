"""Tests for security_scan.output.json_report."""

from __future__ import annotations

import json
from pathlib import Path

from security_scan.output.json_report import JSONReportGenerator


class TestJSONReportGenerator:
    def test_generate_string(self):
        gen = JSONReportGenerator()
        findings = [{"severity": "HIGH", "rule_id": "r1", "file_path": "a.java", "line_number": 1}]
        report_str = gen.generate_string(findings)
        report = json.loads(report_str)
        assert report["tool"] == "security-scan"
        assert report["summary"]["total"] == 1
        assert report["summary"]["by_severity"]["HIGH"] == 1
        assert len(report["findings"]) == 1

    def test_generate_file(self, tmp_path: Path):
        gen = JSONReportGenerator()
        findings = [{"severity": "CRITICAL", "rule_id": "r2", "file_path": "b.java", "line_number": 5}]
        out = tmp_path / "report.json"
        result = gen.generate(findings, str(out))
        assert result == str(out)
        assert out.is_file()
        data = json.loads(out.read_text())
        assert data["summary"]["total"] == 1

    def test_empty_findings(self):
        gen = JSONReportGenerator()
        report_str = gen.generate_string([])
        report = json.loads(report_str)
        assert report["summary"]["total"] == 0
        assert report["findings"] == []
