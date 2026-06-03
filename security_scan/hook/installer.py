"""Git pre-commit hook installer."""


class HookInstaller:
    """Installs security-scan into .git/hooks/pre-commit."""

    def install(self, config: dict) -> bool:
        """Register the pre-commit hook. Returns True on success."""
        ...

    def uninstall(self) -> bool:
        """Remove security-scan from pre-commit hook."""
        ...

    def disable(self) -> bool:
        """Rename hook to .disabled (temporary)."""
        ...

    def enable(self) -> bool:
        """Restore disabled hook."""
        ...
