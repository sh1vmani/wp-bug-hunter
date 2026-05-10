# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""Submission readiness checker for analyzed vulnerability findings."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

import requests

from wp_bug_hunter.analyzer import AnalysisResult, VerificationWalkthrough
from wp_bug_hunter.config import HIGH_CONFIDENCE, REQUEST_TIMEOUT
from wp_bug_hunter.scope import ScopeCheck, verify_scope


MIN_DESCRIPTION_LENGTH: int = 200
MIN_VIDEO_SIZE_BYTES: int = 5 * 1024 * 1024
MIN_SCREENSHOT_COUNT: int = 3

_VIDEO_EXTENSIONS: tuple[str, ...] = (".mp4", ".mov", ".mkv")
_IMAGE_EXTENSIONS: tuple[str, ...] = (".png", ".jpg", ".jpeg")
_WPSCAN_PUBLIC_DB_URL: str = (
    "https://raw.githubusercontent.com/wpscanteam/wpscan-db/master/plugins.json"
)
_wpscan_db: dict | None = None


@dataclass
class VerificationResult:
    """Readiness verdict for one analyzed finding."""

    plugin_slug: str
    plugin_version: str
    pattern_name: str
    ready: bool
    blocking: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    payout_estimate: str = ""
    payout_from_platform: bool = False

    def summary(self) -> None:
        """Print a formatted pass/fail checklist to stdout."""
        status = "PASS" if self.ready else "FAIL"
        bar = "=" * 60
        print(f"\n{bar}")
        print(f"  {self.plugin_slug}  |  {self.pattern_name}  |  {status}")
        print(bar)
        if self.blocking:
            print("  BLOCKING ISSUES:")
            for issue in self.blocking:
                print(f"    [X] {issue}")
        if self.warnings:
            print("  WARNINGS:")
            for w in self.warnings:
                print(f"    [!] {w}")
        if self.ready:
            print("  All checks passed. Ready to submit.")
        print()


def _wpscan_cve_check(
    plugin_slug: str,
    session: requests.Session,
) -> tuple[bool, str]:
    """Return (clear, message) after checking the public WPScan vulnerability database.

    clear=True means no known CVEs were found or the check was inconclusive.
    The database is downloaded once per process and cached in _wpscan_db.
    """
    global _wpscan_db
    if _wpscan_db is None:
        try:
            resp = session.get(_WPSCAN_PUBLIC_DB_URL, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            _wpscan_db = resp.json()
        except requests.RequestException as exc:
            return True, f"WPScan public DB fetch failed ({exc}); CVE check skipped."

    plugin_data = _wpscan_db.get(plugin_slug, {})
    vulns = plugin_data.get("vulnerabilities", [])
    if not vulns:
        return True, ""
    titles = "; ".join(v.get("title", "unknown") for v in vulns[:3])
    return False, f"WPScan lists {len(vulns)} known vulnerability(s): {titles}"


def verify_walkthrough(
    walkthrough: VerificationWalkthrough,
    plugin_slug: str,
    plugin_version: str,
    evidence_dir: str,
    *,
    skip_network: bool = False,
    scope_check: ScopeCheck | None = None,
    cve_result: tuple[bool, str] | None = None,
) -> VerificationResult:
    """Run the pre-submission checklist on one analyzed finding.

    Pass skip_network=True to skip scope and CVE checks when working offline;
    those checks become warnings instead of potential blockers.
    scope_check and cve_result may be pre-computed by verify_analysis to avoid
    redundant HTTP calls when processing multiple findings for the same plugin.
    """
    blocking: list[str] = []
    warnings: list[str] = []

    # Plugin version recorded
    if not plugin_version or plugin_version.strip().lower() == "unknown":
        blocking.append("Plugin version not recorded.")

    # Confidence threshold
    conf = walkthrough.finding.confidence
    if conf < HIGH_CONFIDENCE:
        blocking.append(
            f"Confidence {conf}% is below the required {HIGH_CONFIDENCE}%. "
            "Review the false positive checks before submitting."
        )

    # CVSS score present
    if walkthrough.cvss.score <= 0.0:
        blocking.append("CVSS score is missing or zero.")

    # PoC reproduction steps present
    if not walkthrough.reproduction_steps:
        blocking.append("No reproduction steps recorded.")

    # Description length
    desc_len = len(walkthrough.plain_english)
    if desc_len < MIN_DESCRIPTION_LENGTH:
        blocking.append(
            f"Description is {desc_len} characters; "
            f"minimum required is {MIN_DESCRIPTION_LENGTH}."
        )

    # Evidence directory checks
    if not os.path.isdir(evidence_dir):
        blocking.append(f"Evidence directory not found: {evidence_dir}")
    else:
        all_files = os.listdir(evidence_dir)

        # Video present and large enough
        video_ok = False
        small_video_warnings: list[str] = []
        for fname in all_files:
            if fname.lower().endswith(_VIDEO_EXTENSIONS):
                size = os.path.getsize(os.path.join(evidence_dir, fname))
                if size >= MIN_VIDEO_SIZE_BYTES:
                    video_ok = True
                    break
                small_video_warnings.append(
                    f"{fname} is {size // 1024} KB; "
                    f"recommended minimum is {MIN_VIDEO_SIZE_BYTES // (1024 * 1024)} MB."
                )
        if not video_ok:
            warnings.extend(small_video_warnings)
            blocking.append(
                f"No video >= {MIN_VIDEO_SIZE_BYTES // (1024 * 1024)} MB "
                f"found in {evidence_dir}."
            )

        # Screenshot count
        shots = [f for f in all_files if f.lower().endswith(_IMAGE_EXTENSIONS)]
        if len(shots) < MIN_SCREENSHOT_COUNT:
            blocking.append(
                f"Found {len(shots)} screenshot(s); "
                f"minimum required is {MIN_SCREENSHOT_COUNT}."
            )

    # Scope check and CVE cross-reference
    if skip_network:
        warnings.append("Scope check skipped (offline mode).")
        warnings.append("CVE cross-reference skipped (offline mode).")
    else:
        if scope_check is None:
            scope_check = verify_scope(plugin_slug)
        if not scope_check.overall_in_scope:
            blocking.append(
                f"'{plugin_slug}' was not found in scope on any supported platform. "
                "Confirm the target is accepting reports before submitting."
            )
        if cve_result is None:
            cve_result = _wpscan_cve_check(plugin_slug, requests.Session())
        cve_clear, cve_msg = cve_result
        if not cve_clear:
            blocking.append(
                cve_msg + " Verify this is a new variant before submitting."
            )
        elif cve_msg:
            warnings.append(cve_msg)

    return VerificationResult(
        plugin_slug=plugin_slug,
        plugin_version=plugin_version,
        pattern_name=walkthrough.finding.pattern_name,
        ready=len(blocking) == 0,
        blocking=blocking,
        warnings=warnings,
        payout_estimate=walkthrough.payout_estimate,
        payout_from_platform=walkthrough.payout_from_platform,
    )


def verify_analysis(
    result: AnalysisResult,
    evidence_dir: str,
    *,
    skip_network: bool = False,
) -> list[VerificationResult]:
    """Run the submission checklist on every finding in an AnalysisResult."""
    scope_check: ScopeCheck | None = None
    cve_result: tuple[bool, str] | None = None
    if not skip_network:
        scope_check = verify_scope(result.plugin_slug)
        cve_result = _wpscan_cve_check(result.plugin_slug, requests.Session())
    return [
        verify_walkthrough(
            wt,
            result.plugin_slug,
            result.plugin_version,
            evidence_dir,
            skip_network=skip_network,
            scope_check=scope_check,
            cve_result=cve_result,
        )
        for wt in result.walkthroughs
    ]
