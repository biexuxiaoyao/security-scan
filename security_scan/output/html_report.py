"""HTML report generator."""


class HTMLReportGenerator:
    """Generates a visual HTML scan report."""

    def generate(self, findings: list[dict], output_path: str) -> str:
        """Write HTML report to *output_path*; return the path."""
        ...
