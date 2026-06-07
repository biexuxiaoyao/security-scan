"""File I/O utilities — encoding detection, path normalization, safe reading."""

from __future__ import annotations

import os
from pathlib import Path

# Maximum file size to read (20 MiB).  Larger files are skipped with
# an OSError to prevent OOM on huge log / data files.
DEFAULT_MAX_FILE_SIZE: int = 20 * 1024 * 1024


def read_file_safe(path: str | Path, max_size: int | None = None) -> tuple[str, str, float]:
    """Read file with automatic encoding detection and size limit.

    Parameters
    ----------
    path :
        Path to the file.
    max_size :
        Maximum number of bytes to read.  If ``None``, uses
        ``DEFAULT_MAX_FILE_SIZE`` (20 MiB).  Pass ``0`` to disable.

    Raises
    ------
    OSError
        If the file exceeds *max_size* (and *max_size* is not 0).

    Returns
    -------
    (content, detected_encoding, confidence)
    """
    path = Path(path)
    stat = path.stat()
    size_limit = DEFAULT_MAX_FILE_SIZE if max_size is None else max_size
    if size_limit and stat.st_size > size_limit:
        raise OSError(
            f"File too large ({stat.st_size} > {size_limit} bytes): {path}"
        )
    raw = path.read_bytes()

    # Try UTF-8-SIG first (handles BOM transparently — strips it on decode)
    try:
        text = raw.decode("utf-8-sig")
        # detect whether BOM was actually present
        had_bom = raw.startswith(b"\xef\xbb\xbf")
        return (text, "utf-8-sig" if had_bom else "utf-8", 0.95)
    except UnicodeDecodeError:
        pass

    # Try common Chinese encodings
    for enc in ("gb18030", "gbk", "gb2312"):
        try:
            text = raw.decode(enc)
            return (text, enc, 0.80)
        except (UnicodeDecodeError, LookupError):
            continue

    # Last resort: latin-1 (never fails)
    text = raw.decode("latin-1")
    return (text, "latin-1", 0.30)


def normalize_path(path: str) -> str:
    """Normalize path separators for the current platform.

    On Windows converts forward slashes to backslashes (and vice versa).
    On Unix/macOS ensures forward slashes.
    """
    path = path.strip()
    if os.sep == "\\":
        # Windows — use backslashes, but keep UNC paths intact
        return path.replace("/", "\\")
    # Unix / macOS — use forward slashes
    return path.replace("\\", "/")


def is_supported_extension(file_path: str, extensions: list[str] | None = None) -> bool:
    """Check if *file_path* has a supported file extension.

    If *extensions* is None, uses the default built-in set.
    """
    if extensions is None:
        extensions = [
            ".java", ".xml", ".json", ".yml", ".yaml",
            ".properties", ".txt", ".md",
        ]
    return Path(file_path).suffix.lower() in extensions


def is_binary_file(file_path: str | Path, sample_size: int = 8192) -> bool:
    """Heuristic check: return True if the file appears to be binary."""
    path = Path(file_path)
    if not path.is_file():
        return False
    try:
        # Skip files that exceed the max read size
        stat = path.stat()
        if stat.st_size > DEFAULT_MAX_FILE_SIZE:
            return True  # treat as "binary" (too large to scan)
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        # If null bytes are present, treat as binary
        return b"\0" in chunk
    except OSError:
        return True
