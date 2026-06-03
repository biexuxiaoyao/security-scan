"""Tests for security_scan.output.html_report."""

from __future__ import annotations

from pathlib import Path

from security_scan.output.html_report import HTMLReportGenerator


class TestHTMLReportGenerator:
    def test_generate_string(self):
        gen = HTMLReportGenerator()
        findings = [{"severity": "CRITICAL", "rule_id": "r1", "file_path": "a.java", "line_number": 1, "matched_content": "secret", "description": "test"}]
        html = gen.generate_string(findings)
        assert "security-scan" in html
        assert "CRITICAL" in html or "高危" in html
        assert "a.java" in html

    def test_generate_file(self, tmp_path: Path):
        gen = HTMLReportGenerator()
        findings = [{"severity": "HIGH", "rule_id": "r2", "file_path": "b.java", "line_number": 5}]
        out = tmp_path / "report.html"
        result = gen.generate(findings, str(out))
        assert result == str(out)
        assert out.is_file()
        html = out.read_text()
        assert "security-scan" in html

    def test_empty_findings(self):
        gen = HTMLReportGenerator()
        html = gen.generate_string([])
        assert "未发现安全问题" in html

    def test_encrypted_finding_shows_tag(self):
        gen = HTMLReportGenerator()
        findings = [{"severity": "LOW", "rule_id": "r1", "file_path": "c.java", "line_number": 3, "matched_content": "BEE_xxx", "encrypted": True, "confidence": 0.0}]
        html = gen.generate_string(findings)
        assert "已加密" in html
