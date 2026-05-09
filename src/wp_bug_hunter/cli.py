# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""Command line entry point for wp-bug-hunter."""

import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wp_bug_hunter.analyzer import analyze
from wp_bug_hunter.config import EVIDENCE_DIR, TOOL_NAME, VERSION
from wp_bug_hunter.reporter import generate_report
from wp_bug_hunter.scanner import ScanResult, scan_plugin
from wp_bug_hunter.scope import ScopeCheck, verify_scope
from wp_bug_hunter.verifier import VerificationResult, verify_analysis


EXIT_OK = 0
EXIT_ERROR = 1

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"

COLOR_PASS = "green"
COLOR_WARN = "yellow"
COLOR_FAIL = "red"

CONFIRM_YES = {"y", "Y"}

app = typer.Typer(add_completion=False, help="WordPress plugin bug bounty research tool.")
console = Console()


def _print_banner() -> None:
    """Render the tool banner."""
    console.print(Panel(f"version {VERSION}", title=TOOL_NAME))


def _print_scope_results(scope_check: ScopeCheck) -> None:
    """Print one line per platform scope result."""
    for result in scope_check.results:
        in_scope = "yes" if result.in_scope else "no"
        program = result.program_name if result.program_name else "none"
        console.print(
            f"  {result.platform}: in_scope={in_scope},"
            f" program={program}, confidence={result.confidence}"
        )


def _status_for(verification: VerificationResult) -> tuple[str, str]:
    """Return (status_label, color) for a verification result."""
    if not verification.ready:
        return STATUS_FAIL, COLOR_FAIL
    if verification.warnings:
        return STATUS_WARN, COLOR_WARN
    return STATUS_PASS, COLOR_PASS


def _render_summary_table(
    scan_result: ScanResult,
    verifications: list[VerificationResult],
) -> None:
    """Render the findings summary table to the console."""
    by_pattern = {v.pattern_name: v for v in verifications}

    table = Table(title="Findings Summary")
    table.add_column("Pattern")
    table.add_column("Severity")
    table.add_column("Confidence")
    table.add_column("Status")

    for finding in scan_result.findings:
        verification = by_pattern.get(finding.pattern_name)
        if verification is None:
            status_label, color = STATUS_FAIL, COLOR_FAIL
        else:
            status_label, color = _status_for(verification)
        table.add_row(
            finding.pattern_name,
            finding.severity,
            f"{finding.confidence}%",
            f"[{color}]{status_label}[/{color}]",
        )

    console.print(table)


@app.command()
def scan(
    plugin_slug: str = typer.Argument(..., help="WordPress plugin slug to scan."),
    platform: str = typer.Option("", "--platform", help="Bug bounty platform label stored in the report."),
    skip_network: bool = typer.Option(False, "--skip-network", help="Skip scope and CVE checks (offline mode)."),
    output_dir: str = typer.Option("", "--output-dir", help="Override the reports output directory."),
) -> None:
    """Run the full scan, analyze, verify, and report pipeline for a plugin."""
    try:
        _print_banner()

        if not skip_network:
            scope_check = verify_scope(plugin_slug)
            _print_scope_results(scope_check)
            if not scope_check.overall_in_scope:
                console.print("[yellow]Warning: target not confirmed in scope.[/yellow]")
                answer = input("Target not confirmed in scope. Continue anyway? [y/N]: ")
                if answer not in CONFIRM_YES:
                    console.print("Scan cancelled.")
                    raise typer.Exit(EXIT_OK)

        scan_result = scan_plugin(plugin_slug)
        console.print(
            f"Scanning {plugin_slug}... "
            f"({scan_result.files_scanned} files scanned, {len(scan_result.findings)} findings)"
        )
        if not scan_result.findings:
            console.print("No findings.")
            raise typer.Exit(EXIT_OK)

        console.print(f"Analyzing {len(scan_result.findings)} finding(s)...")
        analysis_result = analyze(scan_result)

        evidence_dir = os.path.join(EVIDENCE_DIR, plugin_slug)
        console.print(f"Verifying {len(scan_result.findings)} finding(s)...")
        verifications = verify_analysis(
            analysis_result, evidence_dir, skip_network=skip_network
        )

        report_path = generate_report(
            analysis_result, verifications, platform=platform, output_dir=output_dir
        )
        console.print(f"Report saved: {report_path}")
        _render_summary_table(scan_result, verifications)

    except typer.Exit:
        raise
    except KeyboardInterrupt:
        console.print("Scan cancelled.")
        raise typer.Exit(EXIT_OK)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(EXIT_ERROR)
