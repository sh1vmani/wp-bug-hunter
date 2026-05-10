# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""Markdown report generator for wp-bug-hunter scan results."""

from __future__ import annotations

import datetime
from pathlib import Path

from wp_bug_hunter.analyzer import (
    AnalysisResult,
    CvssEstimate,
    Finding,
    RecordingGuide,
    VerificationWalkthrough,
)
from wp_bug_hunter.config import OUTPUT_DIR, TOOL_NAME, VERSION
from wp_bug_hunter.verifier import VerificationResult


RISK_CRITICAL_THRESHOLD: float = 9.0
RISK_HIGH_THRESHOLD: float = 7.0
RISK_MEDIUM_THRESHOLD: float = 4.0
RISK_LOW_THRESHOLD: float = 0.1

RISK_CRITICAL = "Critical"
RISK_HIGH = "High"
RISK_MEDIUM = "Medium"
RISK_LOW = "Low"
RISK_INFORMATIONAL = "Informational"

DATE_FORMAT = "%Y-%m-%d"
FILENAME_DATE_FORMAT = "%Y%m%d"

STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"
STATUS_WARN = "WARN"

SECTION_SEPARATOR = "---"
PLATFORM_UNSPECIFIED = "not specified"
NO_VERIFICATION_NOTE = "No verification result found."


def _tc(value: str) -> str:
    """Escape a value for safe insertion into a markdown table cell."""
    return str(value).replace("|", r"\|")


def generate_report(
    result: AnalysisResult,
    verifications: list[VerificationResult],
    platform: str = "",
    output_dir: str = "",
) -> Path:
    """Render a markdown report for the analysis and write it to OUTPUT_DIR."""
    today = datetime.date.today()
    effective_dir = output_dir if output_dir else OUTPUT_DIR
    output_path = Path(effective_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    filename = f"{result.plugin_slug}_{today.strftime(FILENAME_DATE_FORMAT)}.md"
    report_path = output_path / filename

    lines: list[str] = []
    lines.extend(_format_header(result, today, platform))
    lines.extend(_format_executive_summary(result, verifications))

    for walkthrough, verification in zip(result.walkthroughs, verifications):
        lines.append(SECTION_SEPARATOR)
        lines.append("")
        lines.extend(_format_finding_section(walkthrough, verification))

    lines.append(SECTION_SEPARATOR)
    lines.append("")
    lines.extend(_format_recording_appendix(result.walkthroughs))

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def _format_header(
    result: AnalysisResult,
    today: datetime.date,
    platform: str,
) -> list[str]:
    """Render the H1 title and metadata table."""
    platform_value = platform if platform else PLATFORM_UNSPECIFIED
    return [
        f"# {result.plugin_slug} {result.plugin_version}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Scan date | {_tc(today.strftime(DATE_FORMAT))} |",
        f"| Platform | {_tc(platform_value)} |",
        f"| Tool | {_tc(TOOL_NAME)} {_tc(VERSION)} |",
        "",
    ]


def _format_executive_summary(
    result: AnalysisResult,
    verifications: list[VerificationResult],
) -> list[str]:
    """Render the executive summary section."""
    total = len(result.walkthroughs)
    passed = sum(1 for v in verifications if v.ready)
    risk_level = _overall_risk_level(result.walkthroughs)
    summary_paragraph = (
        f"Scan of {result.plugin_slug} {result.plugin_version} produced {total} "
        f"finding(s), of which {passed} passed verification. Overall risk level "
        f"is rated {risk_level} based on the highest CVSS score across all findings."
    )
    return [
        "## Executive Summary",
        "",
        f"- Total findings: {total}",
        f"- Passed verification: {passed}",
        f"- Overall risk level: {risk_level}",
        "",
        summary_paragraph,
        "",
    ]


def _overall_risk_level(walkthroughs: list[VerificationWalkthrough]) -> str:
    """Map the maximum CVSS score across walkthroughs to a qualitative risk label."""
    if not walkthroughs:
        return RISK_INFORMATIONAL
    top_score = max(w.cvss.score for w in walkthroughs)
    if top_score >= RISK_CRITICAL_THRESHOLD:
        return RISK_CRITICAL
    if top_score >= RISK_HIGH_THRESHOLD:
        return RISK_HIGH
    if top_score >= RISK_MEDIUM_THRESHOLD:
        return RISK_MEDIUM
    if top_score >= RISK_LOW_THRESHOLD:
        return RISK_LOW
    return RISK_INFORMATIONAL


def _format_finding_section(
    walkthrough: VerificationWalkthrough,
    verification: VerificationResult | None,
) -> list[str]:
    """Render a single finding's full section."""
    finding = walkthrough.finding
    lines: list[str] = [
        f"## {finding.pattern_name} ({finding.severity})",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Severity | {_tc(finding.severity)} |",
        f"| Confidence | {_tc(finding.confidence)}% |",
        f"| CVSS score | {_tc(walkthrough.cvss.score)} |",
        f"| CVSS vector | `{_tc(walkthrough.cvss.vector)}` |",
        "",
        "### Description",
        "",
        walkthrough.plain_english,
        "",
        "### Attacker Impact",
        "",
        walkthrough.attacker_impact,
        "",
    ]
    lines.extend(_format_cvss_breakdown(walkthrough.cvss))
    lines.extend(_format_numbered("Reproduction Steps", walkthrough.reproduction_steps))
    lines.extend(_format_bullets("Confirmation Criteria", walkthrough.confirmation_criteria))
    lines.extend(_format_bullets("False Positive Checks", walkthrough.false_positive_checks))
    lines.extend(_format_verification_status(verification))
    return lines


def _format_cvss_breakdown(cvss: CvssEstimate) -> list[str]:
    """Render the CVSS components table and overall justification."""
    lines: list[str] = [
        "### CVSS Breakdown",
        "",
        "| Metric | Value | Explanation |",
        "| --- | --- | --- |",
    ]
    for component in cvss.components:
        lines.append(
            f"| {_tc(component.metric)} | {_tc(component.value)} | {_tc(component.explanation)} |"
        )
    lines.append("")
    lines.append(cvss.overall_justification)
    lines.append("")
    return lines


def _format_numbered(heading: str, items: list[str]) -> list[str]:
    """Render an H3 heading followed by a numbered list."""
    lines: list[str] = [f"### {heading}", ""]
    for index, item in enumerate(items, start=1):
        lines.append(f"{index}. {item}")
    lines.append("")
    return lines


def _format_bullets(heading: str, items: list[str]) -> list[str]:
    """Render an H3 heading followed by a bullet list."""
    lines: list[str] = [f"### {heading}", ""]
    for item in items:
        lines.append(f"- {item}")
    lines.append("")
    return lines


def _format_verification_status(verification: VerificationResult | None) -> list[str]:
    """Render the verification status sub-section for one finding."""
    lines: list[str] = ["### Verification Status", ""]
    if verification is None:
        lines.append(f"Status: {STATUS_WARN}")
        lines.append("")
        lines.append(NO_VERIFICATION_NOTE)
        lines.append("")
        return lines

    if verification.ready and not verification.warnings:
        status = STATUS_PASS
    elif verification.ready and verification.warnings:
        status = STATUS_WARN
    else:
        status = STATUS_FAIL
    lines.append(f"Status: {status}")
    lines.append("")

    if not verification.blocking and not verification.warnings:
        lines.append("No issues.")
        lines.append("")
        return lines

    if verification.blocking:
        lines.append("#### Blocking Issues")
        lines.append("")
        for item in verification.blocking:
            lines.append(f"- {item}")
        lines.append("")
    if verification.warnings:
        lines.append("#### Warnings")
        lines.append("")
        for item in verification.warnings:
            lines.append(f"- {item}")
        lines.append("")
    return lines


def _format_recording_appendix(walkthroughs: list[VerificationWalkthrough]) -> list[str]:
    """Render the recording guide appendix covering every walkthrough."""
    lines: list[str] = ["## Appendix: Recording Guide", ""]
    if not walkthroughs:
        return lines
    first_guide = walkthroughs[0].recording_guide
    lines.append(f"Software: {first_guide.software}")
    lines.append("")
    lines.extend(_format_numbered("OBS Setup", first_guide.obs_setup))
    lines.extend(_format_numbered("Before Recording", first_guide.before_recording))
    for walkthrough in walkthroughs:
        lines.extend(_format_recording_guide(walkthrough.finding, walkthrough.recording_guide))
    return lines


def _format_recording_guide(finding: Finding, guide: RecordingGuide) -> list[str]:
    """Render the per-finding recording steps and export settings."""
    lines: list[str] = [
        f"### {finding.pattern_name}",
        "",
    ]
    lines.extend(_format_numbered("Recording Steps", guide.recording_steps))
    lines.append("#### Export")
    lines.append("")
    lines.append(f"- Duration: {guide.duration}")
    lines.append(f"- Format: {guide.export_format}")
    lines.append(f"- Settings: {guide.export_settings}")
    lines.append("")
    return lines
