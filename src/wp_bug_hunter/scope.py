# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""Scope verification against active bug bounty programs."""

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

import requests

from wp_bug_hunter.config import (
    PLATFORMS,
    REQUEST_TIMEOUT,
    MAX_RETRIES,
    RATE_LIMIT_DELAY,
)

# Platform-specific URL templates
PATCHSTACK_ALLIANCE_URL = "https://patchstack.com/bug-bounty/"
PATCHSTACK_PLUGIN_URL = "https://patchstack.com/database/wordpress/plugin/{slug}"
WORDFENCE_PLUGIN_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/{slug}"
HACKERONE_API_URL = "https://api.hackerone.com/v1/hackers/programs"
HACKERONE_SEARCH_URL = "https://hackerone.com/directory/programs?query={query}&filter[type][]=public"
BUGCROWD_SEARCH_URL = "https://bugcrowd.com/programs?sort=recent-activity-desc&program_type=bug-bounty"
INTIGRITI_API_URL = "https://api.intigriti.com/core/researcher/program"
INTIGRITI_SEARCH_URL = "https://app.intigriti.com/programs?search={query}"

# Target type identifiers
TARGET_TYPE_PLUGIN = "wordpress_plugin"
TARGET_TYPE_WEB = "web_target"
TARGET_TYPE_UNKNOWN = "unknown"

# Scope confidence levels
CONFIDENCE_CONFIRMED = "confirmed"
CONFIDENCE_LIKELY = "likely"
CONFIDENCE_UNKNOWN = "unknown"

# WordPress plugin slug: lowercase letters, digits, hyphens only, no dots
_PLUGIN_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
# Rough domain/company pattern
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9\-.]*\.[a-zA-Z]{2,}$")


@dataclass
class ScopeResult:
    """Scope check result for one platform."""

    platform: str
    in_scope: bool
    program_name: str | None
    program_url: str | None
    confidence: str
    notes: str


@dataclass
class ScopeCheck:
    """Aggregated scope check results for a target."""

    target: str
    target_type: str
    results: list[ScopeResult] = field(default_factory=list)
    overall_in_scope: bool = False
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


def detect_target_type(target: str) -> str:
    """
    Detect whether a target is a WordPress plugin slug or a general web target.

    Plugin slugs contain only lowercase letters, digits, and hyphens and have no
    dots. Anything matching a domain pattern is treated as a web target.
    Ambiguous inputs return TARGET_TYPE_UNKNOWN.
    """
    stripped = target.strip()
    lower = stripped.lower()
    if "." not in lower and _PLUGIN_SLUG_RE.match(lower):
        return TARGET_TYPE_PLUGIN
    if _DOMAIN_RE.match(stripped):
        return TARGET_TYPE_WEB
    return TARGET_TYPE_UNKNOWN


def _make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": "wp-bug-hunter/0.1.0 security-research",
            "Accept": "application/json, text/html;q=0.9",
        }
    )
    return session


def _get(
    session: requests.Session, url: str, **kwargs
) -> requests.Response | None:
    """GET with up to MAX_RETRIES attempts. Returns None if all attempts fail."""
    for attempt in range(MAX_RETRIES):
        try:
            return session.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
        except requests.RequestException:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RATE_LIMIT_DELAY)
    return None


def check_patchstack_scope(plugin_slug: str, session: requests.Session) -> ScopeResult:
    """
    Check if a plugin is covered by the Patchstack Alliance bug bounty.

    Patchstack Alliance covers all active publicly-listed WordPress plugins.
    A 200 response from the plugin database page confirms it is tracked.
    """
    url = PATCHSTACK_PLUGIN_URL.format(slug=plugin_slug)
    resp = _get(session, url)

    if resp is None:
        return ScopeResult(
            platform="patchstack",
            in_scope=False,
            program_name=None,
            program_url=PATCHSTACK_ALLIANCE_URL,
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Could not reach Patchstack. Verify manually at {PATCHSTACK_ALLIANCE_URL}",
        )

    if resp.status_code == 200:
        return ScopeResult(
            platform="patchstack",
            in_scope=True,
            program_name="Patchstack Alliance",
            program_url=PATCHSTACK_ALLIANCE_URL,
            confidence=CONFIDENCE_LIKELY,
            notes=f"Plugin page returned HTTP 200 in Patchstack database at {url}",
        )

    if resp.status_code >= 500:
        return ScopeResult(
            platform="patchstack",
            in_scope=False,
            program_name=None,
            program_url=PATCHSTACK_ALLIANCE_URL,
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Patchstack returned server error (HTTP {resp.status_code}). Verify manually.",
        )
    return ScopeResult(
        platform="patchstack",
        in_scope=False,
        program_name=None,
        program_url=PATCHSTACK_ALLIANCE_URL,
        confidence=CONFIDENCE_CONFIRMED,
        notes=f"Plugin not found in Patchstack database (HTTP {resp.status_code}).",
    )


def check_wordfence_scope(plugin_slug: str, session: requests.Session) -> ScopeResult:
    """
    Check if a plugin is tracked by Wordfence Intelligence.

    A 200 response from the Wordfence vulnerability page confirms the plugin
    is indexed, which is required for reporting through their program.
    """
    url = WORDFENCE_PLUGIN_URL.format(slug=plugin_slug)
    resp = _get(session, url)

    if resp is None:
        return ScopeResult(
            platform="wordfence",
            in_scope=False,
            program_name=None,
            program_url=PLATFORMS["wordfence"],
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Could not reach Wordfence. Verify manually at {PLATFORMS['wordfence']}",
        )

    if resp.status_code == 200:
        return ScopeResult(
            platform="wordfence",
            in_scope=True,
            program_name="Wordfence Intelligence",
            program_url=PLATFORMS["wordfence"],
            confidence=CONFIDENCE_LIKELY,
            notes=f"Plugin page returned HTTP 200 in Wordfence Intelligence at {url}",
        )

    if resp.status_code >= 500:
        return ScopeResult(
            platform="wordfence",
            in_scope=False,
            program_name=None,
            program_url=PLATFORMS["wordfence"],
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Wordfence returned server error (HTTP {resp.status_code}). Verify manually.",
        )
    return ScopeResult(
        platform="wordfence",
        in_scope=False,
        program_name=None,
        program_url=PLATFORMS["wordfence"],
        confidence=CONFIDENCE_CONFIRMED,
        notes=f"Plugin not tracked by Wordfence Intelligence (HTTP {resp.status_code}).",
    )


def check_hackerone_scope(query: str, session: requests.Session) -> ScopeResult:
    """
    Check HackerOne public program directory for a target.

    Tries the HackerOne programs API. If authentication is required (HTTP 401
    or 403), returns an unknown result with a manual search URL. If the API
    is reachable, performs a case-insensitive partial name match.
    """
    search_url = HACKERONE_SEARCH_URL.format(query=query)
    if not query.strip():
        return ScopeResult(
            platform="hackerone",
            in_scope=False,
            program_name=None,
            program_url=search_url,
            confidence=CONFIDENCE_UNKNOWN,
            notes="Empty query; HackerOne check skipped.",
        )
    resp = _get(
        session,
        HACKERONE_API_URL,
        params={
            "query": query,
            "sort": "published_at:descending",
            "filter[state][]": "soft_launched",
        },
    )

    if resp is None or resp.status_code in (401, 403):
        return ScopeResult(
            platform="hackerone",
            in_scope=False,
            program_name=None,
            program_url=search_url,
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"HackerOne API requires authentication. Manually verify at: {search_url}",
        )

    if resp.status_code == 200:
        try:
            programs = resp.json().get("data", [])
        except ValueError:
            programs = []

        query_lower = query.lower()
        for program in programs:
            attrs = program.get("attributes", {})
            name = str(attrs.get("name", "")).lower()
            handle = str(attrs.get("handle", "")).lower()
            if query_lower in name or query_lower in handle:
                program_url = f"https://hackerone.com/{attrs.get('handle', '')}"
                return ScopeResult(
                    platform="hackerone",
                    in_scope=True,
                    program_name=attrs.get("name"),
                    program_url=program_url,
                    confidence=CONFIDENCE_LIKELY,
                    notes=f"Partial match in HackerOne programs: '{attrs.get('name')}'",
                )

    return ScopeResult(
        platform="hackerone",
        in_scope=False,
        program_name=None,
        program_url=search_url,
        confidence=CONFIDENCE_UNKNOWN,
        notes=f"Could not confirm HackerOne scope. Manually verify at: {search_url}",
    )


def check_bugcrowd_scope(query: str) -> ScopeResult:
    """
    Check Bugcrowd public program directory for a target.

    Bugcrowd does not expose a public unauthenticated search API. Returns
    an unknown result with a manual search URL for the researcher to verify.
    """
    return ScopeResult(
        platform="bugcrowd",
        in_scope=False,
        program_name=None,
        program_url=BUGCROWD_SEARCH_URL,
        confidence=CONFIDENCE_UNKNOWN,
        notes=f"Bugcrowd requires manual verification. Search for '{query}' at: {BUGCROWD_SEARCH_URL}",
    )


def check_intigriti_scope(query: str, session: requests.Session) -> ScopeResult:
    """
    Check Intigriti public program list for a target.

    Intigriti exposes a public program API that does not require authentication.
    Performs a case-insensitive partial match against program name and handle.
    """
    search_url = INTIGRITI_SEARCH_URL.format(query=query)
    resp = _get(session, INTIGRITI_API_URL)

    if resp is None or resp.status_code != 200:
        return ScopeResult(
            platform="intigriti",
            in_scope=False,
            program_name=None,
            program_url=search_url,
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Could not reach Intigriti API. Verify manually at {search_url}",
        )

    try:
        programs = resp.json()
    except ValueError:
        return ScopeResult(
            platform="intigriti",
            in_scope=False,
            program_name=None,
            program_url=search_url,
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Intigriti API returned unexpected format. Verify manually at {search_url}",
        )

    if not isinstance(programs, list):
        programs = programs.get("data", []) if isinstance(programs, dict) else []
    if not isinstance(programs, list):
        return ScopeResult(
            platform="intigriti",
            in_scope=False,
            program_name=None,
            program_url=search_url,
            confidence=CONFIDENCE_UNKNOWN,
            notes=f"Intigriti API returned unexpected format. Verify manually at {search_url}",
        )

    query_lower = query.lower()
    for program in programs:
        name = str(program.get("name", "")).lower()
        handle = str(program.get("handle", "")).lower()
        if query_lower in name or query_lower in handle:
            program_url = f"https://app.intigriti.com/programs/{program.get('handle', '')}"
            return ScopeResult(
                platform="intigriti",
                in_scope=True,
                program_name=program.get("name"),
                program_url=program_url,
                confidence=CONFIDENCE_LIKELY,
                notes=f"Partial name match in Intigriti programs: '{program.get('name')}'",
            )

    return ScopeResult(
        platform="intigriti",
        in_scope=False,
        program_name=None,
        program_url=search_url,
        confidence=CONFIDENCE_CONFIRMED,
        notes=f"No matching program found in Intigriti public list for '{query}'.",
    )


def verify_scope(target: str) -> ScopeCheck:
    """
    Verify that a target is inside an active bug bounty program.

    For WordPress plugin slugs, checks Patchstack Alliance and Wordfence
    Intelligence. For web targets (domains or company names), checks
    HackerOne, Bugcrowd, and Intigriti. For ambiguous targets, runs all
    five platforms.

    overall_in_scope is True only when at least one platform confirms in scope.
    Callers must inspect confidence on each result before acting on in_scope.
    """
    target = target.strip()
    target_type = detect_target_type(target)
    check = ScopeCheck(target=target, target_type=target_type)

    with _make_session() as session:
        if target_type == TARGET_TYPE_PLUGIN:
            slug = target.lower()
            check.results.append(check_patchstack_scope(slug, session))
            time.sleep(RATE_LIMIT_DELAY)
            check.results.append(check_wordfence_scope(slug, session))

        elif target_type == TARGET_TYPE_WEB:
            check.results.append(check_hackerone_scope(target, session))
            check.results.append(check_bugcrowd_scope(target))
            time.sleep(RATE_LIMIT_DELAY)
            check.results.append(check_intigriti_scope(target, session))

        else:
            slug = target.lower()
            check.results.append(check_patchstack_scope(slug, session))
            time.sleep(RATE_LIMIT_DELAY)
            check.results.append(check_wordfence_scope(slug, session))
            check.results.append(check_hackerone_scope(target, session))
            check.results.append(check_bugcrowd_scope(target))
            time.sleep(RATE_LIMIT_DELAY)
            check.results.append(check_intigriti_scope(target, session))

    check.overall_in_scope = any(r.in_scope for r in check.results)
    return check
