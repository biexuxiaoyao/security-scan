"""Batch processor — splits large finding lists into API-sized batches."""


class BatchProcessor:
    """Manages batching, retries, and fallback for AI classification."""

    def process(self, findings: list[dict], batch_size: int = 20) -> list[dict]:
        """Split into batches, classify, merge results."""
        ...
