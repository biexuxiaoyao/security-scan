"""JSON report generator."""


class JSONReportGenerator:
    """Generates a structured JSON report for CI/tooling integration."""

    def generate(self, findings: list[dict], output_path: str) -> str:
        """Write JSON report to *output_path*; return the path."""
        ...
