"""File I/O utilities — encoding detection, path normalization, safe reading."""

from __future__ import annotations

import os
from pathlib import Path


def read_file_safe(path: str | Path) -> tuple[str, str, float]:
    """Read file with automatic encoding detection.

    Tries encodings in priority order and falls back gracefully.

    Returns
    -------
    (content, detected_encoding, confidence)
    """
    path = Path(path)
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
        with open(path, "rb") as f:
            chunk = f.read(sample_size)
        # If null bytes are present, treat as binary
        return b"\0" in chunk
    except OSError:
        return True
