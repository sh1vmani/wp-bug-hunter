# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""WordPress plugin downloader and vulnerability pattern scanner."""

import pathlib
import re
import shutil
import tempfile
import time
import zipfile
from dataclasses import dataclass

import requests

from wp_bug_hunter.config import (
    TOOL_NAME,
    VERSION,
    WP_PLUGIN_API,
    REQUEST_TIMEOUT,
    MAX_RETRIES,
    RATE_LIMIT_DELAY,
    MEDIUM_CONFIDENCE,
)

# Lines of source shown before and after a finding for display context
CONTEXT_LINES = 3
# Wider line window searched for contextual mitigations (nonce checks, etc.)
CONTEXT_WINDOW = 20
# Byte chunk size when streaming the plugin zip download
DOWNLOAD_CHUNK_SIZE = 8192
# Only PHP files are scanned
PHP_EXTENSION = ".php"
# Skip any single PHP file larger than this to avoid memory pressure
MAX_PHP_FILE_SIZE = 5 * 1024 * 1024

SEVERITY_CRITICAL = "Critical"
SEVERITY_HIGH = "High"
SEVERITY_MEDIUM = "Medium"
SEVERITY_LOW = "Low"

SEVERITY_RANK: dict[str, int] = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
}


@dataclass
class VulnPattern:
    """Definition of one vulnerability pattern applied to every scanned line."""

    name: str
    severity: str
    # Must match the line for the pattern to trigger
    trigger: re.Pattern
    # If found in the line, use confidence_high; otherwise use confidence_low
    user_input_re: re.Pattern | None
    # Found in the same line -> subtract line_mitigation_penalty per match
    line_mitigations: list[re.Pattern]
    # Found in CONTEXT_WINDOW lines around the finding -> subtract context_mitigation_penalty per match
    context_mitigations: list[re.Pattern]
    confidence_high: int
    confidence_low: int
    line_mitigation_penalty: int
    context_mitigation_penalty: int


@dataclass
class Finding:
    """One vulnerability finding in a plugin source file."""

    file_path: str
    line_number: int
    snippet: str
    pattern_name: str
    confidence: int
    confidence_reason: str
    severity: str
    context_before: list[str]
    context_after: list[str]


@dataclass
class ScanResult:
    """All findings from scanning one plugin, sorted by confidence descending."""

    plugin_slug: str
    plugin_version: str
    findings: list[Finding]
    files_scanned: int


# Regex that matches direct user-controlled superglobal access
_USER_INPUT = re.compile(r'\$_(GET|POST|REQUEST|COOKIE)\s*\[')

PATTERNS: list[VulnPattern] = [
    # 1. SQL Injection
    VulnPattern(
        name="SQL Injection",
        severity=SEVERITY_CRITICAL,
        trigger=re.compile(
            r'\$wpdb\s*->\s*(query|get_results|get_var|get_row)\s*\('
        ),
        user_input_re=_USER_INPUT,
        line_mitigations=[
            re.compile(r'\besc_sql\s*\('),
            re.compile(r'\bintval\s*\('),
            re.compile(r'\babsint\s*\('),
            re.compile(r'\bprepare\s*\('),
        ],
        context_mitigations=[],
        confidence_high=88,
        confidence_low=62,
        line_mitigation_penalty=20,
        context_mitigation_penalty=0,
    ),
    # 2. Cross-Site Scripting
    VulnPattern(
        name="Cross-Site Scripting (XSS)",
        severity=SEVERITY_HIGH,
        trigger=re.compile(r'\b(echo|print)\b.*\$'),
        user_input_re=_USER_INPUT,
        line_mitigations=[
            re.compile(r'\besc_html\s*\('),
            re.compile(r'\besc_attr\s*\('),
            re.compile(r'\besc_url\s*\('),
            re.compile(r'\besc_textarea\s*\('),
            re.compile(r'\besc_js\s*\('),
            re.compile(r'\bwp_kses\s*\('),
            re.compile(r'\bsanitize_text_field\s*\('),
            re.compile(r'\bhtmlspecialchars\s*\('),
            re.compile(r'\bhtmlentities\s*\('),
        ],
        context_mitigations=[],
        confidence_high=82,
        confidence_low=52,
        line_mitigation_penalty=20,
        context_mitigation_penalty=0,
    ),
    # 3. Cross-Site Request Forgery
    # Broad trigger; nonce checks in context reduce confidence below threshold
    VulnPattern(
        name="Cross-Site Request Forgery (CSRF)",
        severity=SEVERITY_HIGH,
        trigger=re.compile(r'\$_(POST|REQUEST)\s*\['),
        user_input_re=None,
        line_mitigations=[],
        context_mitigations=[
            re.compile(r'\bwp_verify_nonce\s*\('),
            re.compile(r'\bcheck_ajax_referer\s*\('),
            re.compile(r'\bcheck_admin_referer\s*\('),
        ],
        confidence_high=68,
        confidence_low=68,
        line_mitigation_penalty=0,
        context_mitigation_penalty=30,
    ),
    # 4. File Inclusion
    VulnPattern(
        name="File Inclusion",
        severity=SEVERITY_CRITICAL,
        trigger=re.compile(r'\b(include|require)(_once)?\s*[\(\s].*\$'),
        user_input_re=_USER_INPUT,
        line_mitigations=[
            re.compile(r'\bsanitize_file_name\s*\('),
            re.compile(r'\bbasename\s*\('),
            re.compile(r'\brealpath\s*\('),
            re.compile(r'\bplugin_dir_path\s*\('),
            re.compile(r'\bdirname\s*\('),
        ],
        context_mitigations=[],
        confidence_high=90,
        confidence_low=58,
        line_mitigation_penalty=20,
        context_mitigation_penalty=0,
    ),
    # 5. Arbitrary File Upload
    VulnPattern(
        name="Arbitrary File Upload",
        severity=SEVERITY_HIGH,
        trigger=re.compile(r'\b(move_uploaded_file|wp_handle_upload)\s*\('),
        user_input_re=None,
        line_mitigations=[
            re.compile(r'\bwp_check_filetype\s*\('),
            re.compile(r'\bmime_content_type\s*\('),
        ],
        context_mitigations=[
            re.compile(r'\bwp_check_filetype\s*\('),
            re.compile(r'\ballowed_mime_types\b'),
            re.compile(r'\bin_array\s*\('),
        ],
        confidence_high=68,
        confidence_low=68,
        line_mitigation_penalty=25,
        context_mitigation_penalty=15,
    ),
    # 6. Privilege Escalation
    # Two context mitigations drop confidence below threshold; one alone keeps it visible
    VulnPattern(
        name="Privilege Escalation",
        severity=SEVERITY_HIGH,
        trigger=re.compile(
            r'\b(wp_delete_user|delete_user|update_user_meta|add_user_to_blog|'
            r'update_option|delete_option|wp_insert_user|wp_update_user)\s*\('
        ),
        user_input_re=None,
        line_mitigations=[
            re.compile(r'\bcurrent_user_can\s*\('),
        ],
        context_mitigations=[
            re.compile(r'\bcurrent_user_can\s*\('),
            re.compile(r'\bwp_verify_nonce\s*\('),
            re.compile(r'\bcheck_admin_referer\s*\('),
            re.compile(r'\bcheck_ajax_referer\s*\('),
        ],
        confidence_high=70,
        confidence_low=70,
        line_mitigation_penalty=30,
        context_mitigation_penalty=18,
    ),
    # 7. Open Redirect
    VulnPattern(
        name="Open Redirect",
        severity=SEVERITY_HIGH,
        trigger=re.compile(r'\bwp_redirect\s*\('),
        user_input_re=_USER_INPUT,
        line_mitigations=[
            re.compile(r'\bwp_sanitize_redirect\s*\('),
            re.compile(r'\besc_url\s*\('),
            re.compile(r'\bhome_url\s*\('),
            re.compile(r'\badmin_url\s*\('),
            re.compile(r'\bsite_url\s*\('),
        ],
        context_mitigations=[],
        confidence_high=80,
        confidence_low=48,
        line_mitigation_penalty=20,
        context_mitigation_penalty=0,
    ),
    # 8. PHP Object Injection
    VulnPattern(
        name="PHP Object Injection",
        severity=SEVERITY_CRITICAL,
        trigger=re.compile(r'\bunserialize\s*\('),
        user_input_re=_USER_INPUT,
        line_mitigations=[],
        context_mitigations=[],
        confidence_high=85,
        confidence_low=60,
        line_mitigation_penalty=0,
        context_mitigation_penalty=0,
    ),
    # 9. Remote Code Execution
    VulnPattern(
        name="Remote Code Execution",
        severity=SEVERITY_CRITICAL,
        trigger=re.compile(
            r'\b(eval|system|exec|passthru|shell_exec|popen|proc_open)\s*\('
        ),
        user_input_re=_USER_INPUT,
        line_mitigations=[
            re.compile(r'\bescapeshellarg\s*\('),
            re.compile(r'\bescapeshellcmd\s*\('),
        ],
        context_mitigations=[],
        confidence_high=92,
        confidence_low=65,
        line_mitigation_penalty=25,
        context_mitigation_penalty=0,
    ),
    # 10. Insecure Direct Object Reference
    VulnPattern(
        name="Insecure Direct Object Reference",
        severity=SEVERITY_HIGH,
        trigger=re.compile(
            r'\$wpdb\s*->\s*(get_results|get_row|get_var)\s*\(.*WHERE',
            re.IGNORECASE,
        ),
        user_input_re=_USER_INPUT,
        line_mitigations=[
            re.compile(r'\bintval\s*\('),
            re.compile(r'\babsint\s*\('),
        ],
        context_mitigations=[
            re.compile(r'\bcurrent_user_can\s*\('),
            re.compile(r'\bget_current_user_id\s*\('),
        ],
        confidence_high=75,
        confidence_low=52,
        line_mitigation_penalty=20,
        context_mitigation_penalty=15,
    ),
]


def _make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"{TOOL_NAME}/{VERSION} security-research",
        "Accept": "application/json, text/html;q=0.9",
    })
    return session


def _get_plugin_info(slug: str, session: requests.Session) -> dict:
    """
    Fetch plugin metadata from the WordPress.org plugin info API.

    Returns a dict containing at minimum 'version' and 'download_link'.
    Raises requests.HTTPError if the slug is not found.
    """
    for attempt in range(MAX_RETRIES):
        try:
            resp = session.get(
                WP_PLUGIN_API,
                params={
                    "action": "plugin_information",
                    "slug": slug,
                    "fields": "versions",
                },
                timeout=REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RATE_LIMIT_DELAY)
            else:
                raise
    raise RuntimeError(f"Plugin info fetch failed after {MAX_RETRIES} attempt(s) for '{slug}'.")


def _safe_extract(zf: zipfile.ZipFile, dest: pathlib.Path) -> None:
    """Extract all zip members to dest, skipping entries with path traversal sequences."""
    for member in zf.infolist():
        # Skip symlink entries; their targets are not validated and could point outside dest.
        if member.external_attr >> 16 & 0o170000 == 0o120000:
            continue
        target = dest / member.filename
        try:
            target.resolve().relative_to(dest.resolve())
        except ValueError:
            continue
        zf.extract(member, dest)


def _download_and_extract(
    slug: str, download_url: str, session: requests.Session
) -> pathlib.Path:
    """
    Stream the plugin zip from download_url and extract it to a temporary directory.

    Returns the path to the extracted plugin root. The caller is responsible
    for removing the parent temp directory when finished.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="wp-bug-hunter-"))
    zip_path = tmp / f"{slug}.zip"

    for attempt in range(MAX_RETRIES):
        try:
            with session.get(download_url, stream=True, timeout=REQUEST_TIMEOUT) as resp:
                resp.raise_for_status()
                with zip_path.open("wb") as fh:
                    for chunk in resp.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                        fh.write(chunk)
            break
        except requests.RequestException:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RATE_LIMIT_DELAY)
            else:
                raise

    with zipfile.ZipFile(zip_path) as zf:
        _safe_extract(zf, tmp)

    zip_path.unlink()

    plugin_dir = tmp / slug
    if plugin_dir.is_dir():
        return plugin_dir

    subdirs = [p for p in tmp.iterdir() if p.is_dir()]
    if subdirs:
        return subdirs[0]
    return tmp


def _compute_confidence(
    line: str,
    context_lines: list[str],
    pattern: VulnPattern,
) -> tuple[int, str]:
    """
    Compute a 0-100 confidence score and explanation for one pattern match.

    Returns (score, reason) where reason explains what raised or lowered the score.
    """
    reasons: list[str] = []

    if pattern.user_input_re and pattern.user_input_re.search(line):
        score = pattern.confidence_high
        reasons.append("direct user input present in vulnerable call")
    else:
        score = pattern.confidence_low
        if pattern.user_input_re:
            reasons.append(
                "no direct user input detected; variable may be sanitized upstream"
            )
        else:
            reasons.append(f"{pattern.name} construct detected")

    for mit in pattern.line_mitigations:
        m = mit.search(line)
        if m:
            score -= pattern.line_mitigation_penalty
            reasons.append(f"mitigation '{m.group()}' on same line reduces confidence")

    context_text = "\n".join(context_lines)
    seen: set[str] = set()
    for mit in pattern.context_mitigations:
        m = mit.search(context_text)
        if m and m.group() not in seen:
            score -= pattern.context_mitigation_penalty
            seen.add(m.group())
            reasons.append(
                f"mitigation '{m.group()}' in surrounding context reduces confidence"
            )

    return max(0, min(100, score)), "; ".join(reasons)


def _apply_pattern(
    lines: list[str],
    line_idx: int,
    pattern: VulnPattern,
    rel_path: str,
) -> Finding | None:
    """
    Apply one vulnerability pattern to one line.

    Returns a Finding if the pattern triggers and confidence meets the threshold,
    otherwise returns None.
    """
    line = lines[line_idx]

    if not pattern.trigger.search(line):
        return None

    ctx_start = max(0, line_idx - CONTEXT_LINES)
    ctx_end = min(len(lines), line_idx + CONTEXT_LINES + 1)
    context_before = [ln.rstrip() for ln in lines[ctx_start:line_idx]]
    context_after = [ln.rstrip() for ln in lines[line_idx + 1:ctx_end]]

    win_start = max(0, line_idx - CONTEXT_WINDOW)
    win_end = min(len(lines), line_idx + CONTEXT_WINDOW + 1)
    window = lines[win_start:line_idx] + lines[line_idx + 1:win_end]

    confidence, reason = _compute_confidence(line, window, pattern)

    if confidence < MEDIUM_CONFIDENCE:
        return None

    return Finding(
        file_path=rel_path,
        line_number=line_idx + 1,
        snippet=line.rstrip(),
        pattern_name=pattern.name,
        confidence=confidence,
        confidence_reason=reason,
        severity=pattern.severity,
        context_before=context_before,
        context_after=context_after,
    )


def _scan_php_file(
    file_path: pathlib.Path, plugin_root: pathlib.Path
) -> list[Finding]:
    """
    Scan one PHP file against all patterns.

    Files larger than MAX_PHP_FILE_SIZE are skipped. Unreadable files are
    silently skipped. Returns a (possibly empty) list of findings.
    """
    if file_path.stat().st_size > MAX_PHP_FILE_SIZE:
        return []

    rel_path = str(file_path.relative_to(plugin_root))

    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    lines = text.splitlines()
    findings: list[Finding] = []

    for i, _ in enumerate(lines):
        for pattern in PATTERNS:
            finding = _apply_pattern(lines, i, pattern, rel_path)
            if finding is not None:
                findings.append(finding)

    return findings


def _rank_findings(findings: list[Finding]) -> list[Finding]:
    """
    Sort findings by confidence descending.

    Equal confidence is broken by severity: Critical > High > Medium > Low.
    """
    return sorted(
        findings,
        key=lambda f: (f.confidence, SEVERITY_RANK.get(f.severity, 0)),
        reverse=True,
    )


def _read_version_from_dir(source_dir: pathlib.Path, slug: str) -> str:
    """Read 'Version:' header from readme.txt or <slug>.php; return 'unknown' if absent."""
    for candidate in (source_dir / "readme.txt", source_dir / f"{slug}.php"):
        try:
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                m = re.match(r"(?i)version\s*:\s*(.+)", line.strip())
                if m:
                    return m.group(1).strip()
        except OSError:
            continue
    return "unknown"


def scan_local(slug: str, source_dir: str) -> ScanResult:
    """Scan a local directory of PHP files without downloading from wordpress.org.

    source_dir should point to a directory containing the plugin's PHP files,
    such as the trunk/ or tags/x.y.z/ checkout from the SVN repository.
    """
    plugin_root = pathlib.Path(source_dir).resolve()
    version = _read_version_from_dir(plugin_root, slug)

    findings: list[Finding] = []
    files_scanned = 0

    for php_file in plugin_root.rglob(f"*{PHP_EXTENSION}"):
        try:
            if php_file.stat().st_size > MAX_PHP_FILE_SIZE:
                continue
        except OSError:
            continue
        findings.extend(_scan_php_file(php_file, plugin_root))
        files_scanned += 1

    return ScanResult(
        plugin_slug=slug,
        plugin_version=version,
        findings=_rank_findings(findings),
        files_scanned=files_scanned,
    )


def scan_plugin(slug: str) -> ScanResult:
    """
    Download a WordPress plugin from wordpress.org and scan all PHP files
    for vulnerability patterns.

    Downloads the latest stable version zip, extracts it, scans every PHP
    file against all ten patterns, then removes the temp directory.
    Findings in the returned ScanResult are sorted by confidence descending,
    with severity as the tiebreaker.
    """
    session = _make_session()
    info = _get_plugin_info(slug, session)
    version = str(info.get("version", "unknown"))
    download_url = str(info.get("download_link", ""))

    if not download_url:
        api_error = info.get("error", "")
        detail = f": {api_error}" if api_error else ""
        raise ValueError(f"No download link found for plugin '{slug}'{detail}")

    plugin_dir = _download_and_extract(slug, download_url, session)
    tmp_parent = plugin_dir.parent

    try:
        findings: list[Finding] = []
        files_scanned = 0

        for php_file in plugin_dir.rglob(f"*{PHP_EXTENSION}"):
            try:
                if php_file.stat().st_size > MAX_PHP_FILE_SIZE:
                    continue
            except OSError:
                continue
            findings.extend(_scan_php_file(php_file, plugin_dir))
            files_scanned += 1

        return ScanResult(
            plugin_slug=slug,
            plugin_version=version,
            findings=_rank_findings(findings),
            files_scanned=files_scanned,
        )
    finally:
        shutil.rmtree(tmp_parent, ignore_errors=True)
