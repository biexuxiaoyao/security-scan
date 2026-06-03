"""File I/O utilities — encoding detection, path normalization, safe reading."""


def read_file_safe(path: str) -> tuple[str, str, float]:
    """Read file with automatic encoding detection.

    Returns (content, detected_encoding, confidence).
    """
    ...


def normalize_path(path: str) -> str:
    """Normalize path separators for the current platform."""
    ...
