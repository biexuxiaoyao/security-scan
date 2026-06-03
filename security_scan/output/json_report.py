"""JSON report generator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_scan import __version__


class JSONReportGenerator:
    """Generates a structured JSON report for CI/tooling integration.

    Output schema::

        {
            "tool": "security-scan",
            "version": "0.1.0",
            "generated_at": "2026-06-03T12:00:00Z",
            "summary": {
                "total": 5,
                "by_severity": {"CRITICAL": 1, "HIGH": 2, ...}
            },
            "findings": [ ... ]
        }
    """

    def generate(self, findings: list[dict], output_path: str) -> str:
        """Write JSON report to *output_path*; return the path."""
        report = self._build_report(findings)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return str(path)

    def generate_string(self, findings: list[dict]) -> str:
        """Return the JSON report as a string (no file written)."""
        return json.dumps(
            self._build_report(findings),
            indent=2,
            ensure_ascii=False,
        )

    def _build_report(self, findings: list[dict]) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "LOW")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "tool": "security-scan",
            "version": __version__,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "summary": {
                "total": len(findings),
                "by_severity": by_severity,
            },
            "findings": findings,
        }
