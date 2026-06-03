"""Shell-script template for the pre-commit hook."""

HOOK_TEMPLATE = r"""#!/bin/sh
# security-scan pre-commit hook — DO NOT EDIT
# Managed by: security-scan hook install / uninstall

SCRIPTS="$(git rev-parse --git-dir)/../.git/hooks/security-scan-hook.sh"
if [ -f "$SCRIPTS" ]; then
    . "$SCRIPTS"
fi
"""
