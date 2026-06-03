"""Tests for security_scan.ai.batch_processor."""

from __future__ import annotations

from security_scan.ai.batch_processor import BatchProcessor


class TestBatchProcessor:
    def test_returns_findings_when_ai_disabled(self):
        bp = BatchProcessor({"ai": {"enabled": False}})
        findings = [{"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}]
        result = bp.process(findings)
        assert len(result) == 1
        assert result[0]["ai_reason"] is not None
        assert "unavailable" in result[0]["ai_reason"]

    def test_noop_fallback_adds_ai_fields(self):
        bp = BatchProcessor({"ai": {}})
        findings = [{"severity": "HIGH", "confidence": 0.8, "rule_id": "r1", "file_path": "a.java", "line_number": 1}]
        result = bp._noop_fallback(findings)
        assert result[0]["ai_verdict"] is True
        assert result[0]["ai_confidence"] == 0.0

    def test_demote(self):
        bp = BatchProcessor({})
        assert bp._demote("CRITICAL", 1) == "HIGH"
        assert bp._demote("CRITICAL", 3) == "LOW"
        assert bp._demote("LOW", 1) == "LOW"
        assert bp._demote("UNKNOWN", 1) == "UNKNOWN"
