"""Console output reporter — GBK-safe print on Windows."""

from __future__ import annotations

import sys
from typing import Any

# Ensure stdout/stderr won't crash on Windows GBK consoles
for _stream_name in ("stdout", "stderr"):
    _stream = getattr(sys, _stream_name, None)
    if _stream is not None and hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(errors="replace")
        except OSError:
            pass

SEVERITY_ICONS = {
    "CRITICAL": "\033[91m[CRITICAL]\033[0m",
    "HIGH": "\033[93m[HIGH]\033[0m",
    "MEDIUM": "\033[93m[MEDIUM]\033[0m",
    "LOW": "\033[92m[LOW]\033[0m",
}


class ConsoleReporter:
    """Real-time progress and findings display in terminal."""

    def report(self, findings: list[dict]) -> None:
        """Print formatted findings to stdout."""
        if not findings:
            print("\n\033[92m[OK] No security issues found.\033[0m\n")
            return

        print("\n" + "=" * 60)
        print("  security-scan scan results")
        print("=" * 60)

        # Group by severity
        by_severity: dict[str, list[dict]] = {}
        for f in findings:
            sev = f.get("severity", "LOW")
            by_severity.setdefault(sev, []).append(f)

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            items = by_severity.get(sev, [])
            if not items:
                continue

            icon = SEVERITY_ICONS.get(sev, "[?]")
            print(f"\n{icon}  ({len(items)})")
            print("-" * 60)
            for f in items:
                self._print_finding(f)

        print("=" * 60)
        total = len(findings)
        print(f"  Total: {total} issue{'s' if total != 1 else ''}")
        print()

    def _print_finding(self, f: dict[str, Any]) -> None:
        """Print a single finding to the console."""
        file_path = f.get("file_path", "?")
        line_num = f.get("line_number", "?")
        rule_name = f.get("rule_name", f.get("rule_id", "?"))
        confidence = f.get("confidence", 0.0)
        encrypted = f.get("encrypted", False)
        remediation = f.get("remediation", "")

        tag = " \033[94m[encrypted]\033[0m" if encrypted else ""
        print(f"  {file_path}:{line_num}{tag}")
        print(f"    Rule: {rule_name}  (confidence: {confidence:.0%})")
        print(f"    {f.get('description', '')}")
        if remediation:
            print(f"    \033[90mFix: {remediation}\033[0m")
        print()

    def summary(self, findings: list[dict], elapsed: float | None = None) -> None:
        """Print a short summary line."""
        by_sev: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "LOW")
            by_sev[sev] = by_sev.get(sev, 0) + 1

        parts = [f"total={len(findings)}"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            if by_sev.get(sev):
                parts.append(f"{sev.lower()}={by_sev[sev]}")
        elapsed_str = f" ({elapsed:.2f}s)" if elapsed is not None else ""
        print(f"  Scan complete{elapsed_str} — {', '.join(parts)}", file=sys.stderr)
