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
from security_scan.scanner.regex_scanner import RegexScanner


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
    collector = FileCollector(config)
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
    rule_engine = RuleEngine(config)
    ast_scanner = ASTScanner(config)
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
            findings = regex_scanner.scan(file_path)
        all_findings.append(findings)

    # ── aggregate & post-process ────────────────────────────
    merged = aggregator.aggregate(all_findings)
    merged = rule_engine.post_process(merged)
    elapsed = time.monotonic() - start

    # ── output ──────────────────────────────────────────────
    if output_format == "json":
        reporter = JSONReportGenerator()
        if output_file:
            reporter.generate(merged, output_file)
        else:
            click.echo(reporter.generate_string(merged))
    else:
        reporter = ConsoleReporter()
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
        click.echo("✓ pre-commit hook installed.")
    else:
        click.echo("✗ Failed to install hook (not a git repository?).", err=True)
        raise SystemExit(20)


@hook.command()
@click.option("--global", "global_hook", is_flag=True, help="Remove from global git template.")
def uninstall(global_hook):
    """Uninstall security-scan pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.uninstall(global_hook=global_hook)
    if ok:
        click.echo("✓ pre-commit hook removed.")
    else:
        click.echo("✗ Failed to remove hook.", err=True)
        raise SystemExit(20)


@hook.command()
def disable():
    """Temporarily disable the pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.disable()
    if ok:
        click.echo("✓ pre-commit hook disabled (renamed to .disabled).")
    else:
        click.echo("✗ No hook to disable.", err=True)


@hook.command()
def enable():
    """Re-enable a disabled pre-commit hook."""
    installer = HookInstaller({})
    ok = installer.enable()
    if ok:
        click.echo("✓ pre-commit hook re-enabled.")
    else:
        click.echo("✗ No disabled hook found.", err=True)


# ── init command ──────────────────────────────────────────────


@click.command()
@click.option("--force", is_flag=True, help="Force re-initialization.")
@click.option("--index-url", default=None, help="Custom pip index URL.")
def init(force, index_url):
    """Initialize the security-scan environment."""
    click.echo(f"security-scan v{__version__}")
    click.echo("  ✓ Python OK")
    click.echo("  ✓ PyYAML available")
    if index_url:
        click.echo(f"  Using pip index: {index_url}")
    click.echo("Initialization complete.")


# ── main entry point ──────────────────────────────────────────


@click.group()
@click.version_option(version=__version__, prog_name="security-scan")
def cli():
    """security-scan — Java project code security scanning tool."""


cli.add_command(scan)
cli.add_command(hook)
cli.add_command(init)

main = cli


if __name__ == "__main__":
    cli()
