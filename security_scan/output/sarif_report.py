"""SARIF report generator — compatible with GitHub Code Scanning, GitLab SAST."""


class SARIFReportGenerator:
    """Generates a SARIF 2.1.0 report."""

    def generate(self, findings: list[dict], output_path: str) -> str:
        """Write SARIF report to *output_path*; return the path."""
        ...
