# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""Command line entry point for wp-bug-hunter."""

import os
import traceback

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from wp_bug_hunter.analyzer import AnalysisResult, analyze
from wp_bug_hunter.config import EVIDENCE_DIR, TOOL_NAME, VERSION
from wp_bug_hunter.reporter import generate_report
from wp_bug_hunter.scanner import checkout_and_scan, scan_local, scan_plugin
from wp_bug_hunter.scope import ScopeCheck, get_platform_payout, verify_scope
from wp_bug_hunter.verifier import VerificationResult, verify_analysis


EXIT_OK = 0
EXIT_ERROR = 1

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_NEW = "NEW"
STATUS_CVE = "CVE"

COLOR_PASS = "green"
COLOR_WARN = "yellow"
COLOR_FAIL = "red"
COLOR_NEW = "bright_green"
COLOR_CVE = "blue"

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
    if verification.ready:
        return STATUS_PASS, COLOR_PASS
    if verification.cve_found:
        return STATUS_CVE, COLOR_CVE
    if verification.confidence_passed:
        return STATUS_NEW, COLOR_NEW
    return STATUS_FAIL, COLOR_FAIL


def _short_pattern(name: str) -> str:
    """Map a full pattern name to a short display label for the summary table."""
    replacements = {
        "Cross-Site Request Forgery (CSRF)": "CSRF",
        "Cross-Site Scripting (XSS)": "XSS",
        "SQL Injection": "SQLi",
        "PHP Object Injection": "PHP ObjInject",
        "Arbitrary File Upload": "File Upload",
        "Privilege Escalation": "Priv Escalation",
        "Insecure Direct Object Reference": "IDOR",
        "Remote Code Execution": "RCE",
        "File Inclusion": "File Inclusion",
        "Open Redirect": "Open Redirect",
        "Insecure Deserialization": "Deserial.",
        "Path Traversal": "Path Traversal",
        "Server-Side Request Forgery": "SSRF",
    }
    return replacements.get(name, name[:20])


def _render_summary_table(
    analysis_result: AnalysisResult,
    verifications: list[VerificationResult],
    *,
    show_all: bool = False,
) -> None:
    """Render the findings summary table to the console."""
    table = Table(title="Findings Summary")
    table.add_column("Pattern", min_width=14, max_width=16, no_wrap=True)
    table.add_column("Severity", min_width=8, max_width=8, no_wrap=True)
    table.add_column("Confidence", min_width=10, max_width=10, no_wrap=True)
    table.add_column("Status", min_width=6, max_width=6, no_wrap=True)
    table.add_column("CVE", min_width=4, max_width=5, no_wrap=True)
    table.add_column("Est. Payout", min_width=18, max_width=22, no_wrap=True)

    pairs = [
        (wt, v)
        for wt, v in zip(analysis_result.walkthroughs, verifications)
        if show_all or v.confidence_passed
    ]
    pairs.sort(key=lambda p: p[0].payout_high, reverse=True)
    if not pairs:
        if show_all:
            console.print("No findings found.")
        else:
            console.print(
                "No findings met the confidence threshold. Try --show-all to see everything."
            )
        return
    top_pairs = pairs[:10]
    remaining = len(pairs) - len(top_pairs)
    if remaining > 0:
        console.print(f"Showing top 10 of {len(pairs)} findings by estimated payout. Full list in report.")
    for walkthrough, verification in top_pairs:
        finding = walkthrough.finding
        status_label, color = _status_for(verification)
        table.add_row(
            _short_pattern(finding.pattern_name),
            finding.severity,
            f"{finding.confidence}%",
            f"[{color}]{status_label}[/{color}]",
            f"[red]Yes[/red]" if verification.cve_found else f"[bright_green]No[/bright_green]",
            walkthrough.payout_estimate,
        )

    console.print(table)


@app.command()
def scan(
    plugin_slug: str = typer.Argument(..., help="WordPress plugin slug to scan."),
    platform: str = typer.Option("", "--platform", help="Bug bounty platform label stored in the report."),
    skip_network: bool = typer.Option(False, "--skip-network", help="Skip scope and CVE checks (offline mode)."),
    output_dir: str = typer.Option("", "--output-dir", help="Override the reports output directory."),
    debug: bool = typer.Option(False, "--debug", help="Print full traceback on error."),
    local_dir: str = typer.Option("", "--local-dir", help="Scan a local SVN/source directory instead of downloading."),
    show_all: bool = typer.Option(False, "--show-all", help="Include failed findings in report and summary table (research mode)."),
) -> None:
    """Run the full scan, analyze, verify, and report pipeline for a plugin."""
    try:
        _print_banner()

        evidence_dir = os.path.join(EVIDENCE_DIR, plugin_slug)
        if not os.path.isdir(evidence_dir):
            os.makedirs(evidence_dir, exist_ok=True)
            console.print(f"Evidence directory created: {evidence_dir}")
            console.print(
                f"Place your screen recordings and screenshots in {evidence_dir} "
                "before the verifier runs."
            )
        else:
            console.print(f"Evidence directory: {evidence_dir}")

        if not skip_network:
            scope_check = verify_scope(plugin_slug)
            _print_scope_results(scope_check)
            if not scope_check.overall_in_scope:
                console.print("[yellow]Warning: target not confirmed in scope.[/yellow]")
                answer = input("Target not confirmed in scope. Continue anyway? [y/N]: ")
                if answer.strip().lower() not in {"y", "yes"}:
                    console.print("Scan cancelled.")
                    raise typer.Exit(EXIT_OK)

        if local_dir:
            console.print(f"Using local directory: {local_dir}")
            scan_result = scan_local(plugin_slug, local_dir)
        else:
            console.print(f"Checking out {plugin_slug} from WordPress SVN...")
            try:
                scan_result = checkout_and_scan(plugin_slug)
            except FileNotFoundError:
                console.print(
                    "[yellow]SVN not found, falling back to wordpress.org zip download.[/yellow]"
                )
                scan_result = scan_plugin(plugin_slug)
        console.print(
            f"Scanning {plugin_slug}... "
            f"({scan_result.files_scanned} files scanned, {len(scan_result.findings)} findings)"
        )
        if not scan_result.findings:
            console.print("No findings.")
            raise typer.Exit(EXIT_OK)

        console.print(f"Analyzing {len(scan_result.findings)} finding(s)...")
        payout_range = get_platform_payout(scope_check.results) if not skip_network else None
        analysis_result = analyze(scan_result, payout_range=payout_range)

        console.print(f"Verifying {len(scan_result.findings)} finding(s)...")
        verifications = verify_analysis(
            analysis_result, evidence_dir, skip_network=skip_network
        )

        report_path = generate_report(
            analysis_result, verifications, platform=platform, output_dir=output_dir, show_all=show_all
        )
        console.print(f"Report saved: {report_path}")
        _render_summary_table(analysis_result, verifications, show_all=show_all)

    except typer.Exit:
        raise
    except KeyboardInterrupt:
        console.print("Scan cancelled.")
        raise typer.Exit(EXIT_OK)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        if debug:
            traceback.print_exc()
        raise typer.Exit(EXIT_ERROR)
