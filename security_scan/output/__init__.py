"""Output reporters — console, HTML, JSON, SARIF.

Each reporter exposes a ``generate(findings, output_path)`` or ``report(findings)``
method and can be discovered via the ``list_reporters()`` helper.
"""

from __future__ import annotations

from typing import Any

from security_scan.output.console import ConsoleReporter
from security_scan.output.json_report import JSONReportGenerator
from security_scan.output.html_report import HTMLReportGenerator
from security_scan.output.sarif_report import SARIFReportGenerator


_REPORTERS: dict[str, Any] = {}


def list_reporters() -> list[str]:
    """Return names of available reporters."""
    return list(_REPORTERS.keys())


def get_reporter(name: str):
    """Return a reporter instance by name."""
    return _REPORTERS.get(name)


def register_reporter(name: str, instance: Any) -> None:
    """Register a reporter instance under *name*."""
    _REPORTERS[name] = instance


# Register built-in reporters
register_reporter("console", ConsoleReporter())
register_reporter("json", JSONReportGenerator())
register_reporter("html", HTMLReportGenerator())
register_reporter("sarif", SARIFReportGenerator())
