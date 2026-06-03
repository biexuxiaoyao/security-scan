"""SARIF report generator — compatible with GitHub Code Scanning, GitLab SAST."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from security_scan import __version__

# SARIF 2.1.0 schema version
_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"

_SEVERITY_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

_TOOL_NAME = "security-scan"


class SARIFReportGenerator:
    """Generates a SARIF 2.1.0 report.

    Compatible with:
      - GitHub Code Scanning (auto-detects SARIF on push)
      - GitLab SAST (with gl-sast-report.json)
      - Azure DevOps SARIF SAST Tab
    """

    def generate(self, findings: list[dict], output_path: str) -> str:
        """Write SARIF report to *output_path*; return the path."""
        report = self._build_report(findings)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return str(path)

    def generate_string(self, findings: list[dict]) -> str:
        """Return the SARIF report as a string."""
        return json.dumps(self._build_report(findings), indent=2)

    # ── internal ──────────────────────────────────────────────

    def _build_report(self, findings: list[dict]) -> dict[str, Any]:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Collect unique rule ids
        rule_ids: dict[str, dict] = {}
        for f in findings:
            rid = f.get("rule_id", "unknown")
            if rid not in rule_ids:
                rule_ids[rid] = {
                    "id": rid,
                    "name": f.get("rule_name", rid),
                    "shortDescription": {"text": f.get("description", "")},
                    "fullDescription": {"text": f.get("description", "")},
                    "defaultConfiguration": {"level": _SEVERITY_LEVEL.get(f.get("severity", "LOW"), "note")},
                    "properties": {"precision": "high", "tags": ["security"]},
                }

        results = [self._to_sarif_result(f) for f in findings]

        return {
            "$schema": _SARIF_SCHEMA,
            "version": _SARIF_VERSION,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": _TOOL_NAME,
                            "version": __version__,
                            "informationUri": f"https://github.com/company/security-scan",
                            "rules": list(rule_ids.values()),
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": len(findings) == 0,
                            "endTimeUtc": now,
                        }
                    ],
                }
            ],
        }

    @staticmethod
    def _to_sarif_result(f: dict) -> dict[str, Any]:
        file_path = f.get("file_path", "")
        line = f.get("line_number", 0) or 0
        col = f.get("column_start", 0) or 0
        rule_id = f.get("rule_id", "unknown")
        message = f.get("description", "") or f.get("matched_content", "")
        level = _SEVERITY_LEVEL.get(f.get("severity", "LOW"), "note")

        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        "region": {
                            "startLine": line,
                            "startColumn": col or 1,
                        },
                    }
                }
            ],
        }

        # Attach matched content as a code flow snippet
        matched = f.get("matched_content", "")
        if matched:
            result["codeFlows"] = [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": file_path},
                                            "region": {
                                                "startLine": line,
                                                "snippet": {"text": matched},
                                            },
                                        }
                                    }
                                }
                            ]
                        }
                    ]
                }
            ]

        # Properties
        props: dict[str, Any] = {}
        confidence = f.get("confidence")
        if confidence is not None:
            props["confidence"] = confidence
        encrypted = f.get("encrypted", False)
        if encrypted:
            props["encrypted"] = True
        if props:
            result["properties"] = props

        return result

