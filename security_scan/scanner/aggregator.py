"""Result aggregator — deduplicates, sorts, and merges findings from all scanners."""


class Aggregator:
    """Merges scanner results, removes duplicates, and applies priority ordering."""

    def aggregate(self, results: list[list[dict]]) -> list[dict]:
        """Merge multiple scanner outputs into a single sorted list."""
        ...
