"""Built-in security rules with regex patterns for each scope."""

from __future__ import annotations

import re
from typing import Any

# ── rule schema ──────────────────────────────────────────────────
#
# Each rule is a dict:
#   id            — unique identifier
#   name          — human-readable name
#   scope         — "java" | "properties" | "yaml" | "json" | "xml" | "txt" | "md" | "all"
#   severity      — "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
#   description   — short description
#   pattern       — compiled regex or None (for AST-only rules)
#   pattern_raw   — raw pattern string (for serialization / display)


def _p(p: str) -> re.Pattern:
    """Compile a case-insensitive regex."""
    return re.compile(p, re.IGNORECASE)


BUILTIN_RULES: list[dict[str, Any]] = [
    # ── Java: plaintext password ─────────────────────────────
    {
        "id": "java_plaintext_password",
        "name": "Java plaintext password",
        "scope": "java",
        "severity": "CRITICAL",
        "description": "Plaintext string literal assigned to a password-related variable.",
        "pattern": _p(
            r'(password|passwd|pwd|pass|secret|secret_key|api_key|auth_token|token)\s*'
            r'[=:]\s*"([^"]{4,})"'
        ),
        "pattern_raw": None,  # AST-based — regex is fallback
    },
    # ── Properties / YAML / JSON: credential keys ────────────
    {
        "id": "config_credential_key",
        "name": "Config credential value",
        "scope": "config",  # shorthand for properties, yaml, json
        "severity": "HIGH",
        "description": "A credential-related key in a config file.",
        "pattern": _p(
            r'(?:password|passwd|pwd|pass|secret|api_key|apikey|'
            r'token|private_key|auth_token|connection_string)\s*'
            r'[=:]\s*["\']?([^"\'\]\s,;]{4,})["\']?'
        ),
        "pattern_raw": None,
    },
    # ── Generic: AWS Access Key ──────────────────────────────
    {
        "id": "aws_access_key",
        "name": "AWS Access Key",
        "scope": "all",
        "severity": "HIGH",
        "description": "AWS Access Key ID (AKIA...).",
        "pattern": _p(r'AKIA[0-9A-Z]{16}'),
        "pattern_raw": None,
    },
    # ── Generic: AWS Secret Key ──────────────────────────────
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Key",
        "scope": "all",
        "severity": "HIGH",
        "description": "AWS Secret Access Key.",
        "pattern": _p(
            r'(?i)aws[_-]?(?:secret|access)[_-]?key\s*[=:]\s*["\']?'
            r'([A-Za-z0-9/+=]{40})["\']?'
        ),
        "pattern_raw": None,
    },
    # ── Generic: PEM private key ─────────────────────────────
    {
        "id": "private_key",
        "name": "Private key content",
        "scope": "all",
        "severity": "CRITICAL",
        "description": "PEM-encoded private key block.",
        "pattern": _p(r'-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----'),
        "pattern_raw": None,
    },
    # ── Generic: JWT / Bearer token ──────────────────────────
    {
        "id": "jwt_token",
        "name": "JWT or Bearer token",
        "scope": "all",
        "severity": "HIGH",
        "description": "JWT token or Bearer authorization header value.",
        "pattern": _p(
            r'(?:bearer|token|jwt)\s*[=:]\s*["\']?'
            r'(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)["\']?'
        ),
        "pattern_raw": None,
    },
    # ── Generic: connection string ───────────────────────────
    {
        "id": "connection_string",
        "name": "Connection string with credentials",
        "scope": "all",
        "severity": "CRITICAL",
        "description": "JDBC / Redis / MongoDB connection string containing credentials.",
        "pattern": _p(
            r'(?:jdbc|redis|mongodb|postgresql|mysql)://[^:]+:[^@]+@'
        ),
        "pattern_raw": None,
    },
    # ── Properties: default password values ───────────────────
    {
        "id": "default_password",
        "name": "Default / weak password",
        "scope": "all",
        "severity": "MEDIUM",
        "description": "Common default or weak password values.",
        "pattern": _p(
            r'(?:password|passwd|pwd)\s*[=:]\s*["\']?'
            r'(?:admin|root|password|passw0rd|123456|test|guest|'
            r'default|changeme|qwerty|abc123)["\']?'
        ),
        "pattern_raw": None,
    },
]


def get_rules_for_scope(scope: str) -> list[dict[str, Any]]:
    """Return all built-in rules applicable to *scope*.

    A rule matches if its scope == *scope* or its scope == ``"all"``
    or (for config files) its scope == ``"config"``.
    """
    results = []
    for rule in BUILTIN_RULES:
        if rule["scope"] in (scope, "all"):
            results.append(rule)
        elif scope in ("properties", "yaml", "json", "xml") and rule["scope"] == "config":
            results.append(rule)
    return results


def match_rule_on_line(rule: dict[str, Any], line: str, line_number: int) -> dict | None:
    """Apply a rule's regex pattern to *line*.

    Returns a finding dict if matched, else ``None``.
    """
    pattern: re.Pattern | None = rule.get("pattern")
    if pattern is None:
        return None

    m = pattern.search(line)
    if not m:
        return None

    return {
        "rule_id": rule["id"],
        "rule_name": rule["name"],
        "severity": rule["severity"],
        "description": rule["description"],
        "line_number": line_number,
        "matched_content": m.group(0),
        "confidence": 0.85,  # base confidence; adjusted later by context analyzer
    }
