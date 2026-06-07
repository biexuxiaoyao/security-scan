"""CLI entry point — routes to scan, hook, init sub-commands."""

from __future__ import annotations

import sys
import time

import click

from security_scan import __version__
from security_scan.config.loader import ConfigLoader
from security_scan.hook.installer import HookInstaller
from security_scan.output import list_reporters, get_reporter
from security_scan.output.console import ConsoleReporter
from security_scan.output.json_report import JSONReportGenerator
from security_scan.rules import RuleEngine
from security_scan.scanner.aggregator import Aggregator
from security_scan.scanner.ast_scanner import ASTScanner
from security_scan.scanner.classifier import FileClassifier
from security_scan.scanner.collector import FileCollector
from security_scan.scanner.config_scanner import ConfigKeyValueScanner
from security_scan.scanner.regex_scanner import RegexScanner
from security_scan.utils.file_utils import read_file_safe


def _determine_exit_code(findings: list[dict], config: dict) -> int:
    """Determine process exit code based on findings and config (see 2.9.3)."""
    severity_config = config.get("severity", {})
    block_on_commit = severity_config.get("block_on_commit", ["CRITICAL", "HIGH"])
    min_conf = severity_config.get("min_confidence_to_block", 0.70)

    has_blocked = any(
        f.get("severity") in block_on_commit
        and f.get("confidence", 1.0) >= min_conf
        and not f.get("encrypted", False)
        for f in findings
    )
    if has_blocked:
        return 1  # blocked
    if findings:
        return 2  # findings but below threshold
    return 0


# ── shared options ─────────────────────────────────────────────

_verbose_opt = click.option("-v", "--verbose", count=True, help="Increase verbosity (-v, -vv).")


# ── scan command ───────────────────────────────────────────────


@click.command()
@click.option("--path", default=".", show_default=True, help="Project root path.")
@click.option("--incremental", is_flag=True, help="Scan only git-staged files.")
@click.option("--ci", is_flag=True, help="CI mode (reserved — currently behaves as normal).")
@click.option(
    "--output-format",
    default="console",
    show_default=True,
    help=f"Output format ({', '.join(list_reporters())}).",
)
@click.option("--output-file", default=None, help="Write report to file.")
@click.option("--generate-config", is_flag=True, help="Print default config to stdout and exit.")
@_verbose_opt
def scan(path, incremental, ci, output_format, output_file, generate_config, verbose):
    """Scan a Java project for security issues."""
    # ── dump config mode ────────────────────────────────────
    if generate_config:
        click.echo(ConfigLoader.dump_defaults())
        return

    # ── load config ─────────────────────────────────────────
    loader = ConfigLoader(project_path=path)
    config = loader.load(cli_overrides={"ci": {"enabled": ci}} if ci else None)
    if verbose:
        click.echo(f"Config: {config}", err=True)

    # ── collect files ───────────────────────────────────────
    collector = FileCollector(config, project_path=path)
    if incremental:
        files = collector.collect_incremental()
        if not files:
            click.echo("No staged files to scan.", err=True)
            raise SystemExit(0)
    else:
        files = collector.collect_full(path)

    if not files:
        click.echo("No supported files found to scan.", err=True)
        raise SystemExit(0)

    if verbose:
        click.echo(f"Files to scan: {len(files)}", err=True)

    # ── classify & scan ─────────────────────────────────────
    classifier = FileClassifier(config)
    rule_engine = RuleEngine(config, project_path=path)
    ast_scanner = ASTScanner(config)
    config_kv_scanner = ConfigKeyValueScanner(config)
    regex_scanner = RegexScanner(rule_engine)
    aggregator = Aggregator()

    start = time.monotonic()
    all_findings: list[list[dict]] = []

    for file_path in files:
        strategy = classifier.classify(file_path)
        if strategy == "skip":
            continue
        if strategy == "ast":
            findings = ast_scanner.scan(file_path, rule_engine)
        else:
            # Read once, share between regex and KV scanners
            try:
                file_content, _enc, _conf = read_file_safe(file_path)
            except (OSError, UnicodeDecodeError):
                continue
            findings = regex_scanner.scan(file_path, content=file_content)
            # For config files, also run structured key-value analysis
            kv_findings = config_kv_scanner.scan(file_path, content=file_content)
            findings.extend(kv_findings)
        all_findings.append(findings)

    # ── aggregate & post-process ────────────────────────────
    merged = aggregator.aggregate(all_findings)
    merged = rule_engine.post_process(merged)
    elapsed = time.monotonic() - start

    # ── output ──────────────────────────────────────────────
    reporter = get_reporter(output_format)
    if reporter is None:
        click.echo(f"Unknown output format: {output_format!r}", err=True)
        click.echo(f"Available formats: {', '.join(list_reporters())}", err=True)
        raise SystemExit(20)

    if output_file:
        reporter.generate(merged, output_file)
    elif hasattr(reporter, "generate_string"):
        click.echo(reporter.generate_string(merged))
    else:
        reporter.report(merged)
        reporter.summary(merged, elapsed)

    # ── exit code ───────────────────────────────────────────
    exit_code = _determine_exit_code(merged, config)
    raise SystemExit(exit_code)


# ── hook commands ─────────────────────────────────────────────


@click.group()
def hook():
    """Manage Git pre-commit hooks."""


@hook.command()
@click.option("--global", "global_hook", is_flag=True, help="Install to global git template.")
def install(global_hook):
    """Install security-scan pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.install(global_hook=global_hook)
    if ok:
        click.echo("[OK] pre-commit hook installed.")
    else:
        click.echo("[FAIL] Failed to install hook (not a git repository?).", err=True)
        raise SystemExit(20)


@hook.command()
@click.option("--global", "global_hook", is_flag=True, help="Remove from global git template.")
def uninstall(global_hook):
    """Uninstall security-scan pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.uninstall(global_hook=global_hook)
    if ok:
        click.echo("[OK] pre-commit hook removed.")
    else:
        click.echo("[FAIL] Failed to remove hook.", err=True)
        raise SystemExit(20)


@hook.command()
def disable():
    """Temporarily disable the pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.disable()
    if ok:
        click.echo("[OK] pre-commit hook disabled (renamed to .disabled).")
    else:
        click.echo("[FAIL] No hook to disable.", err=True)


@hook.command()
def enable():
    """Re-enable a disabled pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.enable()
    if ok:
        click.echo("[OK] pre-commit hook re-enabled.")
    else:
        click.echo("[FAIL] No disabled hook found.", err=True)


# ── init command ──────────────────────────────────────────────


@click.command()
@click.option("--force", is_flag=True, help="Force re-initialization.")
@click.option("--index-url", default=None, help="Custom pip index URL.")
@click.option("--offline", is_flag=True, help="Offline mode — skip remote checks.")
@click.option("--deps-dir", default=None, help="Local directory with pre-downloaded wheels.")
def init(force, index_url, offline, deps_dir):
    """Initialize the security-scan environment.

    Checks Python version, verifies / installs dependencies.
    """
    click.echo(f"security-scan v{__version__} — 环境初始化")
    click.echo("=" * 40)

    # 1. Python version check
    py_ok = sys.version_info >= (3, 8)
    click.echo(f"  Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", nl=False)
    if py_ok:
        click.echo(" \033[92m[OK]\033[0m")
    else:
        click.echo(" \033[91m[FAIL] 需要 Python >= 3.8\033[0m")
        raise SystemExit(21)

    # 2. Core dependencies
    _REQUIRED = {"yaml": "PyYAML>=6.0"}
    _OPTIONAL = {
        "chardet": ("chardet>=5.0", "encoding"),
        "javalang": ("javalang>=1.3", "ast"),

    }

    missing = []
    for mod, spec in _REQUIRED.items():
        if _importable(mod):
            click.echo(f"  \033[92m[OK]\033[0m  {spec}")
        else:
            click.echo(f"  \033[91m[FAIL]\033[0m  {spec} — 缺失")
            missing.append(spec)

    for mod, (spec, group) in _OPTIONAL.items():
        if _importable(mod):
            click.echo(f"  \033[92m[OK]\033[0m  {spec}  [{group}]")
        else:
            click.echo(f"  \033[93m[-]\033[0m  {spec}  [{group}] (可选)")

    # 3. Git check
    if _git_available():
        click.echo("  \033[92m[OK]\033[0m  Git")
    else:
        click.echo("  \033[93m[WARN]\033[0m  Git 未安装 — Hook 功能不可用")

    # 4. Auto-install missing core deps
    if missing and not offline:
        click.echo("  尝试自动安装缺失依赖...")
        cmd = [sys.executable, "-m", "pip", "install"]
        if index_url:
            cmd.extend(["--index-url", index_url])
        if deps_dir:
            cmd.extend(["--find-links", deps_dir])
        cmd.extend(missing)
        _pip_install(cmd)

    click.echo("=" * 40)
    click.echo("\033[92m[OK] 初始化完成\033[0m")


def _importable(mod_name: str) -> bool:
    """Return True if *mod_name* can be imported."""
    try:
        __import__(mod_name)
        return True
    except ImportError:
        return False


def _fix_console_encoding() -> None:
    """Reconfigure stdout/stderr for Windows GBK console compatibility.

    On Windows, the default console encoding (cp936 / GBK) cannot represent
    all UTF-8 characters. Setting ``errors='replace'`` prevents
    ``UnicodeEncodeError`` crashes as a safety net (all console output
    symbols are now pure ASCII).
    """
    import sys
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except OSError:
                pass


def _git_available() -> bool:
    """Return True if ``git --version`` succeeds."""
    import subprocess
    try:
        r = subprocess.run(["git", "--version"], capture_output=True, encoding="utf-8", errors="replace", check=False)
        return r.returncode == 0
    except FileNotFoundError:
        return False


def _pip_install(cmd: list[str]) -> None:
    """Run pip install and report result."""
    import subprocess
    click.echo(f"  $ {' '.join(cmd)}", err=True)
    r = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace")
    if r.returncode == 0:
        click.echo("  \033[92m[OK] 依赖安装完成\033[0m")
    else:
        click.echo(f"  \033[91m[FAIL] 安装失败\033[0m", err=True)
        click.echo(f"    {r.stderr.strip()}", err=True)


# ── main entry point ──────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="security-scan")
def cli():
    """security-scan — Java project code security scanning tool."""
    _fix_console_encoding()


cli.add_command(scan)
cli.add_command(hook)
cli.add_command(init)

main = cli


if __name__ == "__main__":
    cli()
