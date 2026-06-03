"""Git pre-commit hook installer."""

from __future__ import annotations

import stat
from pathlib import Path

from security_scan.utils.git_utils import get_repo_root

_HOOK_PATH = ".git/hooks/pre-commit"  # used in _resolve_hook_path
_DISABLED_SUFFIX = ".disabled"

_HOOK_BODY = """\
# security-scan pre-commit hook — DO NOT EDIT THIS LINE
# Managed by: security-scan hook install / uninstall
# Installed at: {timestamp}

SECURITY_SCAN="{security_scan_cmd}"

if command -v "$SECURITY_SCAN" >/dev/null 2>&1; then
    "$SECURITY_SCAN" scan --incremental
    exit_code=$?
    if [ $exit_code -ne 0 ] && [ $exit_code -ne 2 ]; then
        echo "security-scan: blocking commit due to security issues"
        exit $exit_code
    fi
fi
# END security-scan pre-commit hook
"""


class HookInstaller:
    """Installs / uninstalls / disables / enables the pre-commit hook.

    All operations operate on the git repository discovered from ``cwd``.
    """

    MARKER_LINE = "# security-scan pre-commit hook"
    END_MARKER_LINE = "# END security-scan pre-commit hook"

    def __init__(self, config: dict | None = None):
        self.config = config or {}

    # ── public API ─────────────────────────────────────────────

    def install(self, global_hook: bool = False) -> bool:
        """Register the pre-commit hook.

        Parameters
        ----------
        global_hook :
            If True, install into the global git hook template
            (``~/.git-templates/hooks/pre-commit``).

        Returns True on success.
        """
        hook_path = self._resolve_hook_path(global_hook)
        if hook_path is None:
            return False

        body = _HOOK_BODY.format(
            security_scan_cmd="security-scan",
            timestamp=__import__("datetime").datetime.now().isoformat(),
        )

        # Smart merge: if hook exists and doesn't contain our marker, append
        if hook_path.is_file():
            existing = hook_path.read_text(encoding="utf-8")
            if self.MARKER_LINE in existing:
                return True  # already installed
            # existing hook already has a shebang, so we omit it from the body
            script = existing.rstrip() + "\n\n" + body
        else:
            script = "#!/bin/sh\n" + body

        hook_path.parent.mkdir(parents=True, exist_ok=True)
        hook_path.write_text(script, encoding="utf-8")
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True

    def uninstall(self, global_hook: bool = False) -> bool:
        """Remove security-scan content from the pre-commit hook.

        Removes everything between MARKER_LINE and END_MARKER_LINE
        (inclusive).  If only our content remains (plus a shebang),
        deletes the file entirely.
        """
        hook_path = self._resolve_hook_path(global_hook)
        if hook_path is None or not hook_path.is_file():
            return True

        content = hook_path.read_text(encoding="utf-8")
        start = content.find(self.MARKER_LINE)
        if start < 0:
            return True  # not our hook

        end = content.find(self.END_MARKER_LINE, start)
        if end < 0:
            end = len(content)  # malformed — remove everything from start
        else:
            end += len(self.END_MARKER_LINE)

        before = content[:start].strip()
        after = content[end:].strip()

        remaining = "\n".join(p for p in (before, after) if p).strip()
        # If the only remaining content is a shebang line, treat as empty
        if remaining in ("", "#!/bin/sh"):
            hook_path.unlink()
            return True

        hook_path.write_text(remaining + "\n", encoding="utf-8")
        hook_path.chmod(hook_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True

    def disable(self) -> bool:
        """Rename pre-commit hook to ``pre-commit.disabled`` (temporary)."""
        hook_path = self._resolve_hook_path(False)
        if hook_path is None or not hook_path.is_file():
            return False
        disabled = hook_path.with_name(hook_path.name + _DISABLED_SUFFIX)
        hook_path.rename(disabled)
        return True

    def enable(self) -> bool:
        """Restore a disabled hook (rename back from ``.disabled``)."""
        hook_path = self._resolve_hook_path(False)
        if hook_path is None:
            return False
        disabled = hook_path.with_name(hook_path.name + _DISABLED_SUFFIX)
        if not disabled.is_file():
            return False
        disabled.rename(hook_path)
        return True

    # ── helpers ────────────────────────────────────────────────

    def _resolve_hook_path(self, global_hook: bool = False) -> Path | None:
        if global_hook:
            template_dir = Path.home() / ".git-templates" / "hooks"
            return template_dir / "pre-commit"
        repo = get_repo_root()
        if not repo:
            return None
        return Path(repo) / _HOOK_PATH
