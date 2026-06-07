"""Shared encrypted-prefix detection — single source of truth.

All scanners (AST, regex, config KV) should use this module so that
prefix-match logic stays consistent across the codebase.
"""

from __future__ import annotations

from typing import Tuple


def check_encrypted_prefix(
    value: str,
    prefixes: list[str],
) -> Tuple[bool, str | None]:
    """Return ``(is_encrypted, matched_prefix)`` for *value*.

    Parameters
    ----------
    value :
        The raw string value to check (stripped of surrounding quotes
        before calling is recommended — this function only does
        ``str.strip()`` on the input).
    prefixes :
        List of encrypted prefix strings (plain strings, not regex).

    Returns
    -------
    (True, matching_prefix) if *value* starts with any prefix,
    ``(False, None)`` otherwise.
    """
    stripped = value.strip()
    for prefix in prefixes:
        if stripped.startswith(prefix):
            return True, prefix
    return False, None


def extract_value_from_content(content: str) -> str:
    """Extract the value portion from matched content like ``key=value``.

    Tries ``= `` first (avoids breaking on protocol colons in URLs),
    then ``: ``.

    Returns the part after the separator, stripped and unquoted.
    """
    eq_idx = content.find("=") if "=" in content else -1
    colon_idx = content.find(":") if ":" in content else -1

    if eq_idx >= 0 and (colon_idx < 0 or eq_idx < colon_idx):
        value_part = content[eq_idx + 1:]
    elif colon_idx >= 0:
        value_part = content[colon_idx + 1:]
    else:
        value_part = content

    return value_part.strip().strip("\"'")
