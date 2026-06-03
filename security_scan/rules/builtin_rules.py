"""Built-in security rules for plaintext passwords, secrets, tokens etc."""

BUILTIN_RULES: list[dict] = [
    # Java — plaintext password assignment
    {
        "id": "java_plaintext_password",
        "name": "Java plaintext password",
        "scope": "java",
        "severity": "CRITICAL",
        "description": "Detects plaintext string literals assigned to password-related variables.",
    },
    # Properties — password key
    {
        "id": "config_password_value",
        "name": "Config file password value",
        "scope": "properties",
        "severity": "HIGH",
        "description": "Detects values assigned to password-related keys in config files.",
    },
    # Generic — hardcoded secret patterns
    {
        "id": "hardcoded_secret",
        "name": "Hardcoded secret",
        "scope": "all",
        "severity": "HIGH",
        "description": "Matches common secret patterns (AKIA, base64, etc.).",
    },
]
