"""Tests for security_scan.scanner.aggregator."""

from __future__ import annotations

from security_scan.scanner.aggregator import Aggregator


class TestAggregator:
    def test_empty_input(self):
        agg = Aggregator()
        assert agg.aggregate([]) == []

    def test_deduplicates_identical_findings(self):
        agg = Aggregator()
        finding = {
            "file_path": "a.java",
            "line_number": 10,
            "rule_id": "test_rule",
            "severity": "HIGH",
            "confidence": 0.9,
        }
        result = agg.aggregate([[finding], [finding]])
        assert len(result) == 1

    def test_sorts_by_severity_then_confidence(self):
        agg = Aggregator()
        low = {"file_path": "a.java", "line_number": 1, "rule_id": "r1",
               "severity": "LOW", "confidence": 0.5}
        high = {"file_path": "b.java", "line_number": 2, "rule_id": "r2",
                "severity": "HIGH", "confidence": 0.9}
        critical = {"file_path": "c.java", "line_number": 3, "rule_id": "r3",
                    "severity": "CRITICAL", "confidence": 0.95}
        result = agg.aggregate([[low, high, critical]])
        severities = [f["severity"] for f in result]
        assert severities == ["CRITICAL", "HIGH", "LOW"]

    def test_different_findings_all_kept(self):
        agg = Aggregator()
        f1 = {"file_path": "a.java", "line_number": 1, "rule_id": "r1",
              "severity": "HIGH", "confidence": 0.8}
        f2 = {"file_path": "b.java", "line_number": 5, "rule_id": "r2",
              "severity": "MEDIUM", "confidence": 0.7}
        result = agg.aggregate([[f1], [f2]])
        assert len(result) == 2
