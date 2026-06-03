"""Console output reporter."""


class ConsoleReporter:
    """Real-time progress and findings display in terminal."""

    def report(self, findings: list[dict]) -> None:
        """Print formatted findings to stdout."""
        ...
