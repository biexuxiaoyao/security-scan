"""Result aggregator — deduplicates, sorts, and merges findings from all scanners."""

from __future__ import annotations

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class Aggregator:
    """Merges scanner results, removes duplicates, and applies priority ordering.

    Deduplication key: ``(file_path, line_number, rule_id)``.

    Sort order: severity (CRITICAL first), then confidence (desc), then file path.
    """

    def aggregate(self, results: list[list[dict]]) -> list[dict]:
        """Merge multiple scanner outputs into a single sorted list."""
        seen: set[tuple] = set()
        merged: list[dict] = []

        for batch in results:
            for finding in batch:
                key = (
                    finding.get("file_path", ""),
                    finding.get("line_number", 0),
                    finding.get("rule_id", ""),
                )
                if key not in seen:
                    seen.add(key)
                    merged.append(finding)

        merged.sort(key=self._sort_key)
        return merged

    @staticmethod
    def _sort_key(f: dict) -> tuple:
        """Return a sort key for a finding (lower = higher priority)."""
        sev = _SEVERITY_ORDER.get(f.get("severity", "LOW"), 99)
        conf = -f.get("confidence", 0.0)  # descending
        path = f.get("file_path", "")
        return (sev, conf, path)
