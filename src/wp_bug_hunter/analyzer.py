# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

"""Manual verification walkthrough and screen recording guide generator."""

import re
from dataclasses import dataclass

from wp_bug_hunter.config import PURSUIT_CONFIDENCE
from wp_bug_hunter.scanner import Finding, ScanResult

RECORDING_SOFTWARE = "OBS Studio (free) - download at https://obsproject.com"
RECORDING_FORMAT = "MP4"
RECORDING_CODEC = "H.264, 1920x1080, 30fps"
RECORDING_DURATION = "3 to 5 minutes"


@dataclass
class CvssComponent:
    """One metric in a CVSS 3.1 score breakdown."""

    metric: str
    value: str
    explanation: str


@dataclass
class CvssEstimate:
    """Estimated CVSS 3.1 score with full component breakdown."""

    score: float
    vector: str
    components: list[CvssComponent]
    overall_justification: str


@dataclass
class RecordingGuide:
    """Step-by-step screen recording instructions for video evidence."""

    software: str
    obs_setup: list[str]
    before_recording: list[str]
    recording_steps: list[str]
    duration: str
    export_format: str
    export_settings: str


@dataclass
class VerificationWalkthrough:
    """Complete manual verification guide for one finding."""

    finding: Finding
    plain_english: str
    attacker_impact: str
    environment_setup: list[str]
    plugin_install: list[str]
    reproduction_steps: list[str]
    confirmation_criteria: list[str]
    false_positive_checks: list[str]
    severity_justification: str
    cvss: CvssEstimate
    recording_guide: RecordingGuide
    payout_low: int = 0
    payout_high: int = 0
    payout_estimate: str = ""
    payout_from_platform: bool = False


@dataclass
class AnalysisResult:
    """All walkthroughs produced for one plugin scan."""

    plugin_slug: str
    plugin_version: str
    walkthroughs: list[VerificationWalkthrough]


@dataclass
class _PatternTemplate:
    plain_english: str
    attacker_impact: str
    confirmation_criteria: list[str]
    false_positive_checks: list[str]
    severity_justification: str
    cvss_score: float
    cvss_vector: str
    cvss_components: list[tuple[str, str, str]]
    recording_steps: list[str]


_ENV_SETUP_STEPS: list[str] = [
    "Open a terminal on your computer. On Mac: press Command+Space, type Terminal, press Enter. On Windows: press the Windows key, type cmd, press Enter. On Linux: press Ctrl+Alt+T.",
    "Confirm PHP is installed: type 'php --version' and press Enter. You should see output like 'PHP 8.x.x'. If you see 'command not found', install PHP from https://www.php.net/downloads before continuing.",
    "Confirm MySQL is installed: type 'mysql --version' and press Enter. You should see 'mysql  Ver 8.x...'. If not, install MySQL from https://dev.mysql.com/downloads/mysql/ before continuing.",
    "Install WP-CLI. Type this exactly and press Enter: curl -O https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar",
    "Make WP-CLI available system-wide: type 'chmod +x wp-cli.phar && sudo mv wp-cli.phar /usr/local/bin/wp' and press Enter. Enter your computer password when asked.",
    "Confirm WP-CLI works: type 'wp --info' and press Enter. You should see a table with PHP path, WP-CLI version, and OS. If you see an error, repeat the previous step.",
    "Create a folder for your test site: type 'mkdir ~/wp-test && cd ~/wp-test' and press Enter. Your terminal prompt should show you are now inside wp-test.",
    "Download WordPress: type 'wp core download' and press Enter. Wait until you see 'WordPress downloaded.' before continuing.",
    "Create the test database. Type 'mysql -u root -p' and press Enter. Type your MySQL root password when prompted. Then type each of these lines one at a time, pressing Enter after each: CREATE DATABASE wptest;  then  CREATE USER 'wpuser'@'localhost' IDENTIFIED BY 'wppass';  then  GRANT ALL ON wptest.* TO 'wpuser'@'localhost';  then  FLUSH PRIVILEGES;  then type exit and press Enter to leave MySQL.",
    "Create the WordPress config file: type 'wp config create --dbname=wptest --dbuser=wpuser --dbpass=wppass --dbhost=localhost' and press Enter. You should see 'Generated wp-config.php file.'",
    "Install WordPress: type 'wp core install --url=http://localhost:8080 --title=\"Test Site\" --admin_user=admin --admin_password=admin123 --admin_email=test@test.com' and press Enter. You should see 'WordPress installed successfully.'",
    "Start the local web server: type 'php -S localhost:8080' and press Enter. Leave this terminal window open and running. The server must stay running for the site to work.",
    "Open a second terminal window or tab. All remaining commands go in this new window, not the one running the server.",
    "Open your web browser and go to: http://localhost:8080 -- you should see a default WordPress site with a 'Hello World' post.",
    "Log in to WordPress admin: go to http://localhost:8080/wp-admin -- enter username 'admin' and password 'admin123' and click 'Log In'. You should see the WordPress dashboard.",
]

_OBS_SETUP_STEPS: list[str] = [
    "Download OBS Studio for free from https://obsproject.com. Click the download button for your operating system (Windows, Mac, or Linux) and run the installer. Follow all the default prompts.",
    "Open OBS Studio. The first time it opens, an Auto-Configuration Wizard appears. Select 'Optimize for recording, I will not be streaming' and click Next.",
    "On the Video Settings screen, set Base Resolution to 1920x1080 and FPS to 30. Click Next, then Apply Settings.",
    "In the main OBS window, look at the Sources panel in the bottom left. Click the + button and select 'Display Capture'. Name it 'Screen' and click OK. Click OK again on the next dialog. You should now see your desktop displayed in the OBS preview window.",
    "Click Settings in the top menu bar, then click Output on the left. Set Recording Format to MP4. Under Encoder, select 'x264' or 'Hardware (if available)'. Click OK to close Settings.",
    "Do a test recording: click 'Start Recording', wait 15 seconds, click 'Stop Recording'. Open your Videos folder, find the new MP4 file, and play it to confirm your screen is being recorded clearly before doing the real recording.",
]

_BEFORE_RECORDING_STEPS: list[str] = [
    "Close all applications not related to this test. You want only a browser and a terminal visible. A clean desktop looks professional.",
    "Make your browser window as large as possible, at least 1200 pixels wide, so text in the recording is easy to read.",
    "Increase your terminal font size so commands are clearly visible. In Terminal on Mac: Terminal menu > Preferences > Profiles > Text, increase font to 16pt. On Windows: right-click the title bar > Properties > Font, increase size.",
    "Confirm your test WordPress site is running: go to http://localhost:8080 in your browser. If you see a blank page, go back to your server terminal and restart it: type 'php -S localhost:8080'.",
    "Confirm you are logged in: go to http://localhost:8080/wp-admin. If you see the dashboard, you are logged in. If you see a login form, enter admin / admin123.",
    "Confirm the plugin is installed and active: go to http://localhost:8080/wp-admin/plugins.php. The plugin should show a blue 'Deactivate' link.",
    "Navigate to the page where you will demonstrate the vulnerability. This should be the first thing visible when recording starts.",
    "Start OBS recording BEFORE you type any test payload. Click 'Start Recording' in OBS first, then begin demonstrating.",
]

_PAYLOAD_INFO: dict[str, dict[str, str]] = {
    "SQL Injection": {
        "quick_payload": "'",
        "quick_expect": "MySQL syntax error in response (e.g. 'You have an error in your SQL syntax')",
        "burp_payload": "1 AND SLEEP(5)-- -",
        "burp_expect": "Response time delayed by 5 seconds vs the baseline request",
    },
    "Cross-Site Scripting (XSS)": {
        "quick_payload": "<script>alert('XSS')</script>",
        "quick_expect": "JavaScript alert popup showing 'XSS' when the page renders",
        "burp_payload": "<img src=x onerror=alert('XSS')>",
        "burp_expect": "Payload appears unescaped in response HTML body (search the response for 'onerror')",
    },
    "Cross-Site Request Forgery (CSRF)": {
        "quick_payload": "Save the legitimate POST request, then replay it from a different origin (HTML form on a local file)",
        "quick_expect": "Action completes when triggered from the cross-origin page (no 'security check failed' message)",
        "burp_payload": "Right-click request > Engagement tools > Generate CSRF PoC",
        "burp_expect": "PoC HTML, when opened in the same browser session, completes the action server-side",
    },
    "File Inclusion": {
        "quick_payload": "../../../../wp-config.php",
        "quick_expect": "Contents of wp-config.php (DB_PASSWORD, AUTH_KEY constants) appear in the response",
        "burp_payload": "../../../../etc/passwd",
        "burp_expect": "Linux user accounts (root:x:0:0:...) appear in the response body",
    },
    "Arbitrary File Upload": {
        "quick_payload": "Upload a file named test-upload.php with content: <?php echo 'rce_'.phpversion(); ?>",
        "quick_expect": "File accepted; navigating to the upload URL prints 'rce_' followed by the PHP version",
        "burp_payload": "In the multipart/form-data request, change filename to evil.php and Content-Type to image/png",
        "burp_expect": "Server returns the upload URL; that URL executes the PHP payload when fetched",
    },
    "Privilege Escalation": {
        "quick_payload": "Log in as a Subscriber, then trigger the admin action via fetch() in browser console",
        "quick_expect": "Action completes (200 OK with success body) instead of 403 / 'You do not have permission'",
        "burp_payload": "Replay the admin request with the Subscriber's wordpress_logged_in cookie substituted in",
        "burp_expect": "Same successful response as the admin user, proving the capability check is missing",
    },
    "Open Redirect": {
        "quick_payload": "https://example.com",
        "quick_expect": "Browser address bar leaves the WordPress site and lands on example.com",
        "burp_payload": "//example.com  (protocol-relative form, often bypasses naive prefix checks)",
        "burp_expect": "302 response with Location header pointing to the external domain",
    },
    "PHP Object Injection": {
        "quick_payload": "O:8:\"stdClass\":0:{}",
        "quick_expect": "Page accepts the serialized object without raising a deserialization error",
        "burp_payload": "URL-encoded: O%3A8%3A%22stdClass%22%3A0%3A%7B%7D",
        "burp_expect": "200 response, payload accepted -- confirms unserialize() reaches user input",
    },
    "Remote Code Execution": {
        "quick_payload": ";echo 'rce_'.phpversion();  (for eval) or ;id  (for shell_exec)",
        "quick_expect": "'rce_' followed by PHP version, OR 'uid=33(www-data)' style output appears",
        "burp_payload": "URL-encode the payload to survive transport: %3Bid%3B for shell, %3Bphpinfo%28%29%3B for eval",
        "burp_expect": "Command output or phpinfo() page rendered in the response body",
    },
    "Insecure Direct Object Reference": {
        "quick_payload": "Change the ID parameter from your record's ID to another user's ID",
        "quick_expect": "Other user's private data displayed in your session",
        "burp_payload": "In Intruder, set the ID parameter as a payload position and run a numeric range (1-100)",
        "burp_expect": "Multiple users' records returned in the response set, sorted by content length",
    },
}

_FALLBACK_PAYLOAD: dict[str, str] = {
    "quick_payload": "Manual analysis required to determine the right payload for this pattern",
    "quick_expect": "Confirm by reviewing the snippet and surrounding code in the test environment",
    "burp_payload": "Capture the request and craft a payload appropriate to the pattern",
    "burp_expect": "Compare the response to a baseline request to identify the impact",
}

_INPUT_SUPER_RE = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]"
)
_VAR_FROM_INPUT_RE = re.compile(
    r"\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]"
)
_VAR_REF_RE = re.compile(r"\$(\w+)")

_AJAX_HOOK_RE = re.compile(r"add_action\s*\(\s*['\"]wp_ajax(_nopriv)?_(\w+)['\"]")
_REST_RE = re.compile(r"register_rest_route\s*\(\s*['\"]([^'\"]+)['\"]")
_SHORTCODE_RE = re.compile(r"add_shortcode\s*\(\s*['\"](\w+)['\"]")
_ADMIN_PAGE_RE = re.compile(
    r"add_(menu|submenu|options|management|theme|plugins|users|dashboard|posts|media|comments)_page"
)

_NONCE_RE = re.compile(r"\b(wp_verify_nonce|check_ajax_referer|check_admin_referer)\s*\(")
_CAP_RE = re.compile(r"\bcurrent_user_can\s*\(\s*['\"]([^'\"]+)['\"]")
_SANITIZE_NAMES = (
    "sanitize_text_field", "sanitize_email", "sanitize_key", "sanitize_file_name",
    "sanitize_user", "intval", "absint", "esc_sql", "wp_kses", "wp_kses_post",
    "esc_html", "esc_attr", "esc_url", "wp_safe_redirect", "wp_check_filetype",
)
_SANITIZE_RE = re.compile(r"\b(" + "|".join(_SANITIZE_NAMES) + r")\s*\(")


def _extract_input_source(snippet: str, context_before: list[str]) -> dict:
    """Find where user input enters the vulnerable code.

    Returns dict: source ('GET'|'POST'|...|'unknown'), param (name or None),
    var ('$name' or None when input is read directly from a super-global).
    """
    direct = _INPUT_SUPER_RE.search(snippet)
    if direct:
        return {"source": direct.group(1), "param": direct.group(2), "var": None}

    var_map: dict[str, tuple[str, str]] = {}
    for line in context_before:
        for m in _VAR_FROM_INPUT_RE.finditer(line):
            var_map[m.group(1)] = (m.group(2), m.group(3))

    for var in _VAR_REF_RE.findall(snippet):
        if var in var_map:
            source, param = var_map[var]
            return {"source": source, "param": param, "var": f"${var}"}

    return {"source": "unknown", "param": None, "var": None}


def _classify_endpoint(file_path: str, context_before: list[str], slug: str) -> dict:
    """Determine the endpoint type from file path and surrounding hooks."""
    ctx_text = "\n".join(context_before)

    m = _AJAX_HOOK_RE.search(ctx_text)
    if m:
        return {
            "type": "ajax",
            "auth_required": m.group(1) is None,
            "url": "/wp-admin/admin-ajax.php",
            "detail": f"AJAX action 'action={m.group(2)}'",
        }
    m = _REST_RE.search(ctx_text)
    if m:
        return {
            "type": "rest",
            "auth_required": False,
            "url": f"/wp-json/{m.group(1)}/",
            "detail": f"REST namespace '{m.group(1)}' (check permission_callback in surrounding code)",
        }
    m = _SHORTCODE_RE.search(ctx_text)
    if m:
        return {
            "type": "shortcode",
            "auth_required": False,
            "url": f"/?p=PAGE_ID  (any page containing [{m.group(1)}] shortcode)",
            "detail": f"Shortcode [{m.group(1)}]",
        }
    if "wp-admin" in file_path or _ADMIN_PAGE_RE.search(ctx_text):
        return {
            "type": "admin",
            "auth_required": True,
            "url": f"/wp-admin/admin.php?page={slug}",
            "detail": "Admin page",
        }
    return {
        "type": "public",
        "auth_required": False,
        "url": f"/wp-content/plugins/{slug}/{file_path.split('/')[-1]}  (if directly accessible)",
        "detail": "Public-facing PHP file",
    }


def _detect_security_controls(
    context_before: list[str], context_after: list[str]
) -> dict:
    """Search the surrounding code for nonce, capability, and sanitization calls."""
    ctx = "\n".join(context_before + context_after)
    nonce = _NONCE_RE.search(ctx)
    cap = _CAP_RE.search(ctx)
    sanitizers = sorted(set(_SANITIZE_RE.findall(ctx)))
    return {
        "nonce_check": nonce.group(1) if nonce else None,
        "capability_check": cap.group(1) if cap else None,
        "sanitizers": sanitizers,
    }


def _phase1_browser(
    finding: Finding, src: dict, endpoint: dict, payload: dict, controls: dict
) -> list[str]:
    """Build Phase 1 (browser) steps."""
    auth = " (must be logged in)" if endpoint["auth_required"] else " (no login required)"
    steps: list[str] = [
        "PHASE 1 -- Browser quick test:",
        f"Endpoint type: {endpoint['detail']}. Open the URL: {endpoint['url']}{auth}",
    ]
    if src["source"] != "unknown":
        if src["var"]:
            steps.append(
                f"User input enters via $_{src['source']}['{src['param']}'] which is "
                f"assigned to {src['var']} and used at line {finding.line_number}. "
                f"Locate the form field or URL parameter named '{src['param']}'."
            )
        else:
            steps.append(
                f"User input enters directly via $_{src['source']}['{src['param']}']. "
                f"Locate the form field or URL parameter named '{src['param']}'."
            )
    else:
        steps.append(
            f"Inspect the snippet to identify the user input that reaches "
            f"line {finding.line_number}: {finding.snippet}"
        )
    steps.append(f"Supply this payload in '{src['param'] or 'the input'}': {payload['quick_payload']}")
    steps.append(f"Confirm exploitation: {payload['quick_expect']}")
    if controls["nonce_check"]:
        steps.append(
            f"Note: surrounding code calls {controls['nonce_check']}() -- capture a "
            "valid nonce from a normal request before sending the payload."
        )
    if controls["capability_check"]:
        steps.append(
            f"Note: surrounding code calls current_user_can('{controls['capability_check']}'). "
            "Test as a user lacking this capability to confirm the gate is reachable."
        )
    if controls["sanitizers"]:
        steps.append(
            f"Note: surrounding code uses sanitizers ({', '.join(controls['sanitizers'])}). "
            "Try alternative payload encodings if the default is filtered."
        )
    return steps


def _phase2_burp(
    finding: Finding, src: dict, endpoint: dict, payload: dict, controls: dict
) -> list[str]:
    """Build Phase 2 (Burp Suite) steps."""
    steps: list[str] = [
        "PHASE 2 -- Burp Suite PoC:",
        "Open Burp Suite Community Edition (preinstalled on Kali). Go to Proxy > "
        "Intercept and click 'Open browser' to launch the embedded browser, OR "
        "configure Firefox to proxy through 127.0.0.1:8080 manually.",
        "Trust the Burp CA: in the Burp browser, navigate to http://burp, download "
        "the CA certificate, and import it under Firefox Settings > Privacy & "
        "Security > Certificates > View Certificates > Authorities > Import.",
    ]
    if endpoint["auth_required"]:
        steps.append(
            "Through the Burp browser, log in to WordPress with the appropriate role "
            "so the session cookie is captured."
        )
    steps.append(
        f"In the Burp browser, navigate to {endpoint['url']} and trigger one normal "
        "request to the vulnerable endpoint."
    )
    steps.append(
        "In Burp's Proxy > HTTP history, locate the request and right-click > Send to Repeater."
    )
    if src["param"] and src["source"] != "unknown":
        location = "POST body" if src["source"] in ("POST", "FILES") else (
            "Cookie header" if src["source"] == "COOKIE" else "URL query string"
        )
        steps.append(
            f"In Repeater, locate the parameter '{src['param']}' in the {location} "
            f"and replace its value with the payload: {payload['burp_payload']}"
        )
    else:
        steps.append(f"In Repeater, modify the request to inject: {payload['burp_payload']}")
    steps.append("Click Send.")
    steps.append(f"Confirm in the response panel: {payload['burp_expect']}")
    steps.append(
        "Save the Repeater tab as evidence: right-click the tab > Save > Selected "
        "items > save as burp-poc.json next to your video."
    )
    return steps


def _phase3_evidence(finding: Finding, endpoint: dict, controls: dict) -> list[str]:
    """Build Phase 3 (evidence checklist) steps."""
    steps: list[str] = [
        "PHASE 3 -- Evidence checklist:",
        "Screenshot 1 (browser): vulnerability triggered. URL bar visible. If "
        "logged in, the user identity must be visible in the WordPress admin bar.",
        "Screenshot 2 (Burp request): Repeater request panel showing the HTTP "
        "request with the payload highlighted in the parameter.",
        "Screenshot 3 (Burp response): Repeater response panel showing the proof "
        "of exploitation (error, injected content, file contents, etc.).",
        "Screen recording: 2-5 minute MP4 capturing the full reproduction from "
        "login through observing the exploit. See the Recording Guide appendix.",
    ]
    if endpoint["auth_required"]:
        role_hint = "admin" if endpoint["type"] == "admin" else "logged-in user (test as Subscriber for least-privilege impact)"
        steps.append(f"Authentication: this finding requires a {role_hint} session.")
    else:
        steps.append("Authentication: not required; exploitable as an anonymous visitor.")
    if controls["nonce_check"] or controls["capability_check"] or controls["sanitizers"]:
        present: list[str] = []
        if controls["nonce_check"]:
            present.append(f"{controls['nonce_check']}()")
        if controls["capability_check"]:
            present.append(f"current_user_can('{controls['capability_check']}')")
        if controls["sanitizers"]:
            present.append(f"sanitizers({', '.join(controls['sanitizers'])})")
        steps.append(
            "Security controls observed in surrounding code: "
            + "; ".join(present)
            + ". Document in your write-up why these did not prevent exploitation."
        )
    return steps


def _build_repro_steps(finding: Finding, slug: str, version: str) -> list[str]:
    """Generate three-phase reproduction steps from actual finding data."""
    src = _extract_input_source(finding.snippet, finding.context_before)
    endpoint = _classify_endpoint(finding.file_path, finding.context_before, slug)
    payload = _PAYLOAD_INFO.get(finding.pattern_name, _FALLBACK_PAYLOAD)
    controls = _detect_security_controls(finding.context_before, finding.context_after)
    steps: list[str] = []
    steps.extend(_phase1_browser(finding, src, endpoint, payload, controls))
    steps.extend(_phase2_burp(finding, src, endpoint, payload, controls))
    steps.extend(_phase3_evidence(finding, endpoint, controls))
    return steps


_PATTERN_TEMPLATES: dict[str, _PatternTemplate] = {
    "SQL Injection": _PatternTemplate(
        plain_english=(
            "SQL injection happens when a plugin puts data from a visitor directly into a "
            "database command without cleaning it first. WordPress uses MySQL to store all "
            "site data. When a plugin builds a database query by gluing user-supplied text "
            "directly into the query, an attacker can type specially crafted text that "
            "breaks out of the data and becomes part of the command itself. The scanner "
            "found this pattern in {file} at line {line}: {snippet}"
        ),
        attacker_impact=(
            "An attacker can read every row in every table of the WordPress database. "
            "This includes all usernames, hashed passwords, email addresses, private posts, "
            "WooCommerce orders, personal data, and any secrets stored by other plugins. "
            "Depending on MySQL configuration, they may also be able to write files to the "
            "server, which can lead to complete server takeover."
        ),
        confirmation_criteria=[
            "A MySQL error message appears on the page mentioning SQL syntax or mysqli.",
            "The page responds 5 seconds late with the SLEEP(5) payload.",
            "Database name or user() value appears on the page with the UNION SELECT payload.",
            "Page content changes in an unexpected way when a quote is added to the input.",
        ],
        false_positive_checks=[
            "Check whether the variable fed into the query is actually sanitized before this line. Search the plugin's PHP files for sanitize_text_field, intval, absint, or esc_sql applied to the same variable name. If found, the vulnerability may not be exploitable.",
            "Check whether the parameter requires authentication. If only Administrators can supply this input, the risk is lower but may still be reportable depending on the program's scope.",
            "Verify the query actually runs by triggering it in your test environment. If you cannot make the page produce a MySQL error or delayed response, it may be a false positive.",
            "Confirm the variable is not type-cast to an integer before use. A (int) cast before the query means string injection is impossible.",
        ],
        severity_justification=(
            "SQL injection is rated Critical because it allows an unauthenticated attacker "
            "on the internet to read all data from the database with no user interaction "
            "required. No special skill or account is needed. The impact is complete loss "
            "of confidentiality of all stored data."
        ),
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "The vulnerability is exploitable over the internet from any location."),
            ("Attack Complexity", "Low (AC:L)", "No special conditions, race conditions, or configuration needed to exploit."),
            ("Privileges Required", "None (PR:N)", "An attacker does not need any account or login to exploit this."),
            ("User Interaction", "None (UI:N)", "No victim needs to click anything. The attacker exploits it directly."),
            ("Scope", "Unchanged (S:U)", "The impact stays within the WordPress application and its database."),
            ("Confidentiality", "High (C:H)", "All data in the database is exposed including credentials and private content."),
            ("Integrity", "High (I:H)", "An attacker can modify or delete database records."),
            ("Availability", "High (A:H)", "An attacker can drop tables or lock the database, taking the site offline."),
        ],
        recording_steps=[
            "Start OBS recording now. Show your browser on the WordPress test site. Navigate to the page that triggers the vulnerability.",
            "Show the URL bar clearly. Point out the parameter you will be testing.",
            "Type a single quote ' in the input and submit. Show the full page response including any error message.",
            "Type the SLEEP payload: 1 AND SLEEP(5)-- - and submit. Show the browser loading indicator and the 5-second delay.",
            "Type the extraction payload: 1 UNION SELECT 1,user(),database()-- - and submit. Show the database output on screen.",
            "Open browser developer tools (F12 > Network tab) and show the exact request and response for the final payload.",
            "Stop recording. Total time should be 3 to 5 minutes.",
        ],
    ),

    "Cross-Site Scripting (XSS)": _PatternTemplate(
        plain_english=(
            "Cross-site scripting happens when a plugin takes text from a user and prints "
            "it directly onto a webpage without converting special characters. Web browsers "
            "treat angle brackets and certain symbols as HTML and JavaScript instructions. "
            "When a plugin echoes user input without escaping these characters, an attacker "
            "can inject script tags that the browser will execute as real JavaScript code. "
            "The scanner found this pattern in {file} at line {line}: {snippet}"
        ),
        attacker_impact=(
            "An attacker can inject JavaScript that runs in the browser of any visitor who "
            "views the affected page. This JavaScript can steal session cookies to hijack "
            "admin accounts, redirect users to phishing pages, log every keystroke, silently "
            "create new admin accounts, or deface the site. Stored XSS is especially severe "
            "because it affects every visitor automatically."
        ),
        confirmation_criteria=[
            "An alert popup appears showing the text 'XSS' when the payload is submitted.",
            "The browser executes JavaScript from user-supplied input.",
            "For stored XSS: the payload fires in a fresh browser session without re-submitting.",
        ],
        false_positive_checks=[
            "Check if the output is inside a JavaScript string already. If the echo is inside a <script> tag with quotes around the variable, the escaping rules are different and the standard payload may not work.",
            "Check if a Content Security Policy (CSP) header is set. In browser dev tools, go to Network, click the page response, and look for 'Content-Security-Policy' in the headers. A strict CSP can block script execution even if injection is present.",
            "Check whether the input passes through sanitize_text_field or wp_kses before being stored. Search the plugin code for these functions applied to the same variable name.",
            "Verify your payload actually appears unescaped in the HTML source. In the browser, right-click and select View Page Source. Search for your payload text. If you see &lt;script&gt; instead of <script>, the output is being escaped and this is a false positive.",
        ],
        severity_justification=(
            "XSS is rated High because it allows an attacker to execute arbitrary JavaScript "
            "in victims' browsers, enabling account takeover without needing the victim's "
            "password. Stored XSS affecting admin pages is especially critical as it can "
            "lead to full site compromise."
        ),
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "The attacker delivers the payload over the internet."),
            ("Attack Complexity", "Low (AC:L)", "No special conditions needed beyond finding the injection point."),
            ("Privileges Required", "None (PR:N)", "For reflected XSS no login is needed. Adjust to Low if login is required to submit the payload."),
            ("User Interaction", "Required (UI:R)", "A victim must visit the page or click a link containing the payload."),
            ("Scope", "Changed (S:C)", "The injected script runs in the victim's browser context, crossing from server to client scope."),
            ("Confidentiality", "Low (C:L)", "Attacker can read cookies and page content from the victim's session."),
            ("Integrity", "Low (I:L)", "Attacker can modify page content seen by the victim and perform actions on their behalf."),
            ("Availability", "None (A:N)", "XSS alone does not affect site availability."),
        ],
        recording_steps=[
            "Start OBS recording. Show the WordPress test site in your browser.",
            "Navigate to the page containing the vulnerable input. Show the URL bar.",
            "Type the XSS payload into the input field on camera: <script>alert('XSS')</script>",
            "Submit the form or press Enter. Show the alert popup appearing on screen.",
            "Dismiss the popup. Open browser developer tools (F12), click the Elements tab, and show the unescaped script tag in the HTML source.",
            "If testing stored XSS: open a new incognito window, navigate to the same page URL, and show the popup firing without any input.",
            "Show the Network tab in dev tools to display the request and response.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "Cross-Site Request Forgery (CSRF)": _PatternTemplate(
        plain_english=(
            "Cross-site request forgery tricks a logged-in user's browser into sending a "
            "request to WordPress that the user did not intend. Browsers automatically "
            "include login cookies with every request to a site. If a plugin processes "
            "form submissions without checking a secret nonce token, an attacker can host "
            "a page elsewhere that silently posts to the plugin's endpoint the moment a "
            "logged-in admin visits it. The scanner found POST data being processed in "
            "{file} at line {line} without a nonce check in the surrounding code: {snippet}"
        ),
        attacker_impact=(
            "An attacker can craft a webpage that, when visited by a logged-in WordPress "
            "admin, silently performs any action the plugin allows without the admin's "
            "knowledge. This can include deleting content, changing settings, creating "
            "accounts, or any other state-changing operation the plugin supports."
        ),
        confirmation_criteria=[
            "The WordPress action completes successfully when triggered from the external HTML file.",
            "No nonce field appears in the form data captured in browser dev tools.",
            "The plugin does not reject the request or show a 'Security check failed' message.",
        ],
        false_positive_checks=[
            "Search the plugin's PHP code for wp_verify_nonce, check_ajax_referer, and check_admin_referer. The scanner checks the 20 lines around the finding but the nonce check could be in a parent function. Trace the call stack to see if verification happens at a higher level.",
            "Check if the action only works for administrators. If only admins can perform it and the result is not sensitive, the program may consider it low priority.",
            "Confirm there is genuinely no nonce field in the form HTML. In browser dev tools, inspect the form element and look for a hidden input with a name like _wpnonce or nonce.",
        ],
        severity_justification=(
            "CSRF is rated Medium to High depending on what action it triggers. When CSRF "
            "can cause an admin to perform a privileged action without knowing it, the "
            "impact is significant even though it requires social engineering the admin "
            "to visit a malicious page."
        ),
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "The attacker delivers the malicious page over the internet."),
            ("Attack Complexity", "Low (AC:L)", "Creating the malicious form requires no special skill."),
            ("Privileges Required", "None (PR:N)", "The attacker needs no account on the site. The victim's session is used."),
            ("User Interaction", "Required (UI:R)", "A logged-in admin must visit the attacker's page."),
            ("Scope", "Unchanged (S:U)", "Impact is contained to the WordPress application."),
            ("Confidentiality", "None (C:N)", "CSRF performs actions but does not expose data to the attacker directly."),
            ("Integrity", "High (I:H)", "The attacker can change WordPress data or settings through the victim's session."),
            ("Availability", "None (A:N)", "CSRF alone does not cause denial of service."),
        ],
        recording_steps=[
            "Start OBS recording. Show your browser logged in to the WordPress admin.",
            "Navigate to the plugin's page that contains the vulnerable form. Show the form on screen.",
            "Open browser dev tools (F12 > Network tab). Submit the form normally and show the POST request with no nonce field in the payload.",
            "Open csrf-test.html in the same browser window while still logged in. Show the URL bar showing it is a local file, not the WordPress site.",
            "Click the submit button. Show the page response.",
            "Navigate back to the WordPress admin and show that the action completed, proving it was triggered cross-site.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "File Inclusion": _PatternTemplate(
        plain_english=(
            "File inclusion happens when a plugin uses a variable to determine which file "
            "to load with PHP's include or require statement, and that variable can be "
            "controlled by a visitor. PHP executes any included file as code. If an attacker "
            "can manipulate the filename, they can make the server load a sensitive system "
            "file or, in some configurations, execute code from a remote server. The scanner "
            "found an include or require using a variable in {file} at line {line}: {snippet}"
        ),
        attacker_impact=(
            "At minimum an attacker can read any file the web server has access to, "
            "including wp-config.php which contains the database password and secret keys. "
            "In configurations where allow_url_include is enabled, an attacker can load "
            "and execute PHP code from a server they control, resulting in complete server "
            "compromise."
        ),
        confirmation_criteria=[
            "Contents of wp-config.php appear in the page response, showing DB_PASSWORD or secret keys.",
            "Contents of /etc/passwd appear showing system user accounts.",
            "The page displays file contents not normally shown when the parameter is absent.",
        ],
        false_positive_checks=[
            "Check whether the variable is filtered before use. Search for basename(), realpath(), sanitize_file_name(), or plugin_dir_path() applied to the variable. These restrict what file can be loaded.",
            "Check if the include path is built by concatenating a hardcoded directory prefix that prevents path traversal. For example, include(PLUGIN_DIR . $file) where $file cannot start with ../ if the prefix is checked.",
            "Verify the variable actually comes from user input by tracing its assignment. If it is only set from a database value that the user cannot control, it may not be exploitable.",
        ],
        severity_justification=(
            "File inclusion is rated Critical because successful exploitation exposes "
            "database credentials and in some server configurations allows arbitrary "
            "code execution. Reading wp-config.php alone provides enough access to "
            "completely compromise the WordPress site."
        ),
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "Exploitable from the internet by any user."),
            ("Attack Complexity", "Low (AC:L)", "Only requires crafting a URL with a path traversal string."),
            ("Privileges Required", "None (PR:N)", "No login or account needed if the endpoint is public."),
            ("User Interaction", "None (UI:N)", "No victim action needed. Attacker exploits directly."),
            ("Scope", "Unchanged (S:U)", "Impact stays within the server's file system access."),
            ("Confidentiality", "High (C:H)", "All files the web server can read are exposed."),
            ("Integrity", "High (I:H)", "With RFI or code execution, attacker can write files."),
            ("Availability", "High (A:H)", "Code execution can disable the site or encrypt files."),
        ],
        recording_steps=[
            "Start OBS recording. Show your browser and a terminal side by side.",
            "Show the plugin installed and active at http://localhost:8080/wp-admin/plugins.php.",
            "In the browser address bar, type the vulnerable URL with the path traversal payload: http://localhost:8080/?PARAMETER=../../../../wp-config.php",
            "Show the full page response displaying the contents of wp-config.php including DB_PASSWORD.",
            "Open browser dev tools (F12 > Network) and show the exact request URL and the response body.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "Arbitrary File Upload": _PatternTemplate(
        plain_english=(
            "Arbitrary file upload happens when a plugin allows users to upload files "
            "but does not properly check what type of file is being uploaded. WordPress "
            "is powered by PHP, and if an attacker can upload a PHP file to the server, "
            "they can access it through a URL and cause the server to execute it as code. "
            "The scanner found file upload handling code in {file} at line {line} "
            "without file type validation nearby: {snippet}"
        ),
        attacker_impact=(
            "An attacker can upload a PHP webshell file to the server and then access it "
            "via a URL to execute arbitrary system commands. This gives them the ability "
            "to read any file on the server, write new files, delete files, connect to "
            "other systems, and in most cases achieve complete server compromise."
        ),
        confirmation_criteria=[
            "A PHP file with .php extension was accepted by the upload form.",
            "The uploaded PHP file is accessible via a URL in the browser.",
            "When accessed, the browser shows the PHP echo output (not the raw source), confirming server-side execution.",
        ],
        false_positive_checks=[
            "Check if the file was actually renamed on upload. Some plugins accept the upload but rename it with a safe extension or hash. Confirm the file you uploaded is accessible under its original name.",
            "Check if wp_check_filetype() or a mime-type validation is called before move_uploaded_file() in the surrounding code. Search the plugin for these functions.",
            "Confirm the uploads directory is accessible via HTTP. Some servers block direct access to the uploads folder. If navigating to the uploaded file gives a 403 Forbidden, PHP execution via upload is not possible.",
        ],
        severity_justification=(
            "Arbitrary file upload is rated High to Critical depending on whether PHP "
            "execution is possible. Even without PHP execution, uploading arbitrary files "
            "can lead to stored XSS through SVG files or content injection. With PHP "
            "execution, the impact is full remote code execution."
        ),
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "The upload form is accessible over the internet."),
            ("Attack Complexity", "Low (AC:L)", "No special conditions needed beyond finding the upload form."),
            ("Privileges Required", "Low (PR:L)", "Usually requires at minimum a logged-in Subscriber or Author account. Adjust to None if the upload is unauthenticated."),
            ("User Interaction", "None (UI:N)", "No other user needs to take any action."),
            ("Scope", "Unchanged (S:U)", "Impact contained to the web server."),
            ("Confidentiality", "High (C:H)", "Code execution exposes all server files."),
            ("Integrity", "High (I:H)", "Attacker can write, modify, or delete files."),
            ("Availability", "High (A:H)", "Attacker can disable the site or consume resources."),
        ],
        recording_steps=[
            "Start OBS recording. Show your browser on the plugin's upload interface.",
            "Show the test-upload.php file you created in a text editor so the viewer can see its contents.",
            "Select and upload the PHP file using the plugin's interface. Show the upload succeeding.",
            "Navigate to http://localhost:8080/wp-content/uploads/ and locate the uploaded file. Show it in the directory listing.",
            "Click on the uploaded test-upload.php URL. Show the browser executing it and displaying the PHP version output.",
            "Open browser dev tools (F12 > Network) and show the request for the PHP file and the response body.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "Privilege Escalation": _PatternTemplate(
        plain_english=(
            "Privilege escalation happens when a plugin performs a sensitive action "
            "without first checking whether the current user is allowed to do it. "
            "WordPress has a role system where Subscribers, Authors, Editors, and "
            "Administrators have different permissions. If a function that should only "
            "be usable by an Administrator can also be triggered by a Subscriber, "
            "that lower-privileged user can perform actions far beyond what they should "
            "be allowed to do. The scanner found a sensitive WordPress function in "
            "{file} at line {line} without a capability check nearby: {snippet}"
        ),
        attacker_impact=(
            "An attacker with any level of WordPress account (even a Subscriber, which "
            "anyone can register for on sites with open registration) can perform "
            "administrative actions. This can include deleting other users, modifying "
            "site settings, promoting themselves to Administrator, or accessing private data."
        ),
        confirmation_criteria=[
            "A Subscriber-level user can trigger the sensitive function successfully.",
            "The database or settings change actually occurs when triggered by the low-privilege account.",
            "No 'You do not have permission' or 403 error is returned.",
        ],
        false_positive_checks=[
            "Trace the full call stack. The capability check might be in a parent function that calls this one. Search the plugin for current_user_can() and check if it wraps the call path to this line.",
            "Check if the action is registered only for logged-in users with a specific role. Some hooks only fire in contexts where capability is already implied.",
            "Confirm the Subscriber can actually trigger the code path. If the action is only registered for the admin menu and the Subscriber cannot access that menu, the code may be unreachable.",
        ],
        severity_justification=(
            "Privilege escalation is rated High because it breaks the trust boundaries "
            "of the WordPress role system. An attacker with a basic account can perform "
            "administrative operations, potentially taking over the site entirely by "
            "promoting their own account to Administrator."
        ),
        cvss_score=8.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "The vulnerable action is triggered over the network via HTTP."),
            ("Attack Complexity", "Low (AC:L)", "No special conditions needed beyond having a low-privilege account."),
            ("Privileges Required", "Low (PR:L)", "Requires at minimum a Subscriber account to trigger the action."),
            ("User Interaction", "None (UI:N)", "The attacker triggers it directly, no other user needs to act."),
            ("Scope", "Unchanged (S:U)", "Impact stays within the WordPress application."),
            ("Confidentiality", "High (C:H)", "Access to admin functions can expose all site data."),
            ("Integrity", "High (I:H)", "Attacker can modify users, settings, and content."),
            ("Availability", "High (A:H)", "Attacker could delete content or disable the site."),
        ],
        recording_steps=[
            "Start OBS recording. Show two browser windows side by side: one logged in as admin, one in incognito as the Subscriber.",
            "In the admin window, show the WordPress user list to confirm both accounts exist.",
            "In the incognito window (Subscriber), trigger the vulnerable action using the method found in the reproduction steps. Show the request being made.",
            "Show the response confirming the action succeeded (no permission error).",
            "Switch to the admin window and show the effect of the action in WordPress (changed setting, deleted user, etc.).",
            "Open dev tools in the Subscriber window and show the network request with the Subscriber's session cookie.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "Open Redirect": _PatternTemplate(
        plain_english=(
            "Open redirect happens when a plugin uses a value from user input to decide "
            "where to send the browser after an action, without checking that the "
            "destination is within the same website. Attackers use open redirects to "
            "make phishing links look legitimate: a link to a trusted site that quietly "
            "forwards the user to a malicious site. The scanner found wp_redirect() "
            "called in {file} at line {line} with a potentially unvalidated value: {snippet}"
        ),
        attacker_impact=(
            "An attacker can craft a URL on the victim site that appears to link to the "
            "legitimate WordPress site but silently redirects the user to a phishing page. "
            "Because the link starts with the real domain, users and security tools are "
            "more likely to trust it. This is commonly used in phishing campaigns and "
            "to steal OAuth tokens or session cookies."
        ),
        confirmation_criteria=[
            "The browser navigates to an external domain after visiting a WordPress URL.",
            "The redirect destination is controlled entirely by a URL parameter the user supplies.",
            "No validation or restriction is applied to prevent external domains.",
        ],
        false_positive_checks=[
            "Check if wp_sanitize_redirect() or esc_url() is applied to the value before it is passed to wp_redirect(). These functions do not fully prevent open redirect but reduce the attack surface.",
            "Check if wp_safe_redirect() is used instead of wp_redirect(). wp_safe_redirect() only allows redirects to the same site by default and would make this a non-issue.",
            "Verify the redirect actually goes to an external domain in your test. If the site checks the value and strips external URLs, there is no vulnerability.",
        ],
        severity_justification=(
            "Open redirect is rated Medium. It does not directly compromise the server "
            "but enables highly convincing phishing attacks that leverage the reputation "
            "of the victim site. Some bug bounty programs rate this Low, others Medium, "
            "depending on the business impact."
        ),
        cvss_score=6.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "The malicious link is delivered over the internet."),
            ("Attack Complexity", "Low (AC:L)", "Only requires adding a redirect parameter to the URL."),
            ("Privileges Required", "None (PR:N)", "No account needed to construct the redirect URL."),
            ("User Interaction", "Required (UI:R)", "The victim must click the crafted link."),
            ("Scope", "Changed (S:C)", "The user ends up on a different domain from where they started."),
            ("Confidentiality", "Low (C:L)", "Can be used to capture credentials or tokens on the destination phishing page."),
            ("Integrity", "Low (I:L)", "The attacker controls what the user sees after being redirected."),
            ("Availability", "None (A:N)", "Does not affect site availability."),
        ],
        recording_steps=[
            "Start OBS recording. Show your browser at the WordPress test site.",
            "In the address bar, type the redirect URL with the external destination: http://localhost:8080/?PARAMETER=https://example.com and press Enter.",
            "Show the browser navigating away from localhost:8080 and arriving at example.com.",
            "Show the browser address bar confirming the destination is example.com.",
            "Go back and show the browser history or use dev tools Network tab to show the redirect response (HTTP 302) with the Location header pointing to example.com.",
            "Stop recording. Aim for 2 to 3 minutes.",
        ],
    ),

    "PHP Object Injection": _PatternTemplate(
        plain_english=(
            "PHP object injection happens when a plugin passes user-supplied data to "
            "unserialize(), a PHP function that reconstructs objects from a text "
            "representation. An attacker can craft a specially formatted string that, "
            "when unserialized, creates objects of existing PHP classes. If any class "
            "in the codebase has magic methods like __wakeup or __destruct that perform "
            "dangerous actions, the attacker's crafted string can trigger those actions "
            "without ever calling them directly. The scanner found unserialize() in "
            "{file} at line {line}: {snippet}"
        ),
        attacker_impact=(
            "Depending on what PHP classes are available in the codebase (called a "
            "gadget chain), PHP object injection can lead to arbitrary file reads, "
            "arbitrary file writes, SQL injection, or remote code execution. Even "
            "without an obvious gadget chain in the plugin itself, WordPress core "
            "and popular libraries often contain usable gadgets."
        ),
        confirmation_criteria=[
            "A serialized string supplied by the user is accepted by the application without error.",
            "The application behaves differently based on the structure of the serialized input.",
            "A serialized object of type stdClass is accepted without a type mismatch error.",
        ],
        false_positive_checks=[
            "Check if the value being unserialized comes from a signed cookie or HMAC-verified source. If the data is signed with a secret key before serialization and verified before unserialization, injection is not possible.",
            "Check if the input passes through base64_decode before unserialize. While base64 is not a security control, confirming the input format helps understand the attack surface.",
            "Verify the parameter actually reaches the unserialize call by testing with an invalid serialized value like 'INVALID' and checking if an error appears in the response.",
        ],
        severity_justification=(
            "PHP object injection is rated Critical because it can lead to remote code "
            "execution when a usable gadget chain exists. Even without an obvious chain, "
            "the vulnerability class is inherently Critical due to the potential impact "
            "and the difficulty of ruling out all gadget chains in complex codebases."
        ),
        cvss_score=9.8,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "Exploitable by sending a crafted HTTP request over the internet."),
            ("Attack Complexity", "Low (AC:L)", "Crafting a serialized payload requires basic PHP knowledge but no special environment."),
            ("Privileges Required", "None (PR:N)", "No account required if the endpoint accepting the data is public."),
            ("User Interaction", "None (UI:N)", "The attacker exploits it directly without needing a victim."),
            ("Scope", "Unchanged (S:U)", "Impact contained to the server running WordPress."),
            ("Confidentiality", "High (C:H)", "Code execution exposes all server data."),
            ("Integrity", "High (I:H)", "Attacker can write files and modify data."),
            ("Availability", "High (A:H)", "Attacker can disable the service."),
        ],
        recording_steps=[
            "Start OBS recording. Show a terminal window alongside your browser.",
            "Show the vulnerable parameter being sent normally: use browser dev tools (F12 > Network) to show a real request to the endpoint.",
            "In the terminal, generate the test payload: php -r \"echo serialize(new stdClass());\" and show the output.",
            "Send the request with the serialized payload using the browser address bar or dev tools Network tab Edit and Resend.",
            "Show the response confirming the payload was accepted without error.",
            "In the terminal, run: grep -r '__wakeup\\|__destruct' . and show any magic method matches in the plugin directory.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "Remote Code Execution": _PatternTemplate(
        plain_english=(
            "Remote code execution happens when a plugin passes user-supplied data to a "
            "function that executes it as system commands or PHP code. Functions like "
            "eval() execute strings as PHP code. Functions like shell_exec() and system() "
            "run strings as operating system commands. If an attacker can control what "
            "string is passed to these functions, they can run any code or command on "
            "the server. The scanner found one of these functions in {file} at line "
            "{line}: {snippet}"
        ),
        attacker_impact=(
            "Complete server compromise. An attacker can read, write, or delete any file "
            "the web server has access to, run any operating system command, connect to "
            "other servers on the internal network, install backdoors that persist after "
            "the vulnerability is patched, and in most cases escalate to root privileges "
            "using local privilege escalation techniques."
        ),
        confirmation_criteria=[
            "'rce_confirmed' or PHP version output appears in the page response from the eval payload.",
            "System user identity or command output appears from a shell_exec payload.",
            "phpinfo() page renders when the payload is injected.",
        ],
        false_positive_checks=[
            "Check if escapeshellarg() or escapeshellcmd() wraps the input before the shell function call. These functions make shell injection very difficult though not always impossible.",
            "Check if eval() is called on a hardcoded string or a value read from the database that users cannot modify. Trace the full data path from the function argument back to its source.",
            "Verify the payload actually executes by testing with a timing payload: inject sleep(5); for eval() or sleep 5 for shell functions and check if the response is delayed 5 seconds.",
        ],
        severity_justification=(
            "Remote code execution is rated Critical, the highest possible severity. "
            "It gives an attacker complete control of the server with no limitations. "
            "This is the most serious class of vulnerability and is almost always "
            "rated 9.0 or above on CVSS regardless of context."
        ),
        cvss_score=10.0,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "Exploitable from the internet by sending an HTTP request."),
            ("Attack Complexity", "Low (AC:L)", "No race conditions or special configuration required."),
            ("Privileges Required", "None (PR:N)", "No account required if the endpoint is public. Adjust to Low or High if authentication is required."),
            ("User Interaction", "None (UI:N)", "The attacker exploits it directly."),
            ("Scope", "Changed (S:C)", "Execution escapes the web application and affects the underlying operating system."),
            ("Confidentiality", "High (C:H)", "All data on the server is exposed."),
            ("Integrity", "High (I:H)", "Attacker can create, modify, or delete any file."),
            ("Availability", "High (A:H)", "Attacker can crash or permanently disable the server."),
        ],
        recording_steps=[
            "Start OBS recording. Show a terminal and browser side by side.",
            "Show the plugin installed and active in WordPress admin.",
            "Identify and show the vulnerable input field or URL parameter in the browser.",
            "Type the harmless RCE payload: ;echo('rce_confirmed_'.phpversion()); for eval, or ;echo rce_confirmed for shell commands.",
            "Submit the request and show 'rce_confirmed' appearing in the page response.",
            "Show the request and response in browser dev tools (F12 > Network tab) with the payload clearly visible.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),

    "Insecure Direct Object Reference": _PatternTemplate(
        plain_english=(
            "Insecure direct object reference happens when a plugin retrieves database "
            "records by an ID number that comes from user input, without checking whether "
            "the current user is actually allowed to see that record. If you change the "
            "ID number in a URL from your own record's ID to someone else's ID and the "
            "plugin returns their data, that is an IDOR vulnerability. The scanner found "
            "a database query with a WHERE clause using potentially user-supplied values "
            "in {file} at line {line}: {snippet}"
        ),
        attacker_impact=(
            "An attacker can access private data belonging to other users by guessing or "
            "iterating through ID numbers. This can expose private posts, order details, "
            "personal information, private messages, or any other user-specific data "
            "stored in the WordPress database."
        ),
        confirmation_criteria=[
            "User A can view data created by or belonging to User B by changing the ID in the URL.",
            "Private records are returned to users who did not create them.",
            "No authorization check prevents cross-user access to the data.",
        ],
        false_positive_checks=[
            "Check if the query result is filtered after retrieval to only show records belonging to the current user. The vulnerable line might fetch all records but a later filter may remove records the user should not see.",
            "Check if current_user_can() or a user ID comparison is done elsewhere in the same function before the data is returned or displayed.",
            "Verify the data is actually private. If all records in the plugin are intended to be public, IDOR may not apply.",
        ],
        severity_justification=(
            "IDOR is rated Medium to High depending on the sensitivity of the data exposed. "
            "Access to private posts or user-specific data is High. Access to non-sensitive "
            "public-intent data is Low. The severity should be adjusted based on what "
            "data is actually retrievable."
        ),
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        cvss_components=[
            ("Attack Vector", "Network (AV:N)", "Exploited by sending an HTTP request over the internet."),
            ("Attack Complexity", "Low (AC:L)", "Only requires changing an ID number in the URL."),
            ("Privileges Required", "Low (PR:L)", "Requires a logged-in account, typically a Subscriber."),
            ("User Interaction", "None (UI:N)", "The attacker exploits it directly, no other user involved."),
            ("Scope", "Unchanged (S:U)", "Impact stays within the WordPress application."),
            ("Confidentiality", "High (C:H)", "Private data belonging to other users is exposed."),
            ("Integrity", "None (I:N)", "IDOR alone typically only reads data, not modifies it. Adjust if write operations are also unprotected."),
            ("Availability", "None (A:N)", "Does not affect site availability."),
        ],
        recording_steps=[
            "Start OBS recording. Show two browser windows: one for User A (attacker), one for User B (victim).",
            "In User B's window, show creating a private record using the plugin and note its ID from the URL.",
            "In User A's window, show the URL being modified to use User B's ID instead of User A's.",
            "Show User B's private data appearing in User A's session. Make the username in the WordPress admin bar visible to confirm which user is logged in.",
            "Show the URL bar clearly so the ID parameter is visible.",
            "Open browser dev tools (F12 > Network) in User A's window and show the response body containing the unauthorized data.",
            "Stop recording. Aim for 3 to 5 minutes.",
        ],
    ),
}

_FALLBACK_TEMPLATE = _PatternTemplate(
    plain_english=(
        "A potential vulnerability was detected in {file} at line {line}. "
        "The vulnerable code is: {snippet}"
    ),
    attacker_impact="Impact depends on the specific vulnerability. Review the finding manually.",
    confirmation_criteria=[
        "The vulnerability produces an unintended result when malicious input is supplied.",
    ],
    false_positive_checks=[
        "Verify the input actually reaches the vulnerable code path in a running instance of the plugin.",
    ],
    severity_justification="Severity must be determined by manual analysis of the specific code.",
    cvss_score=5.0,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
    cvss_components=[
        ("Attack Vector", "Network (AV:N)", "Assumed network exploitable pending manual review."),
        ("Attack Complexity", "Low (AC:L)", "Assumed low complexity pending manual review."),
        ("Privileges Required", "None (PR:N)", "Assumed no privileges required pending manual review."),
        ("User Interaction", "None (UI:N)", "Assumed no user interaction required pending manual review."),
        ("Scope", "Unchanged (S:U)", "Impact scope to be determined by manual review."),
        ("Confidentiality", "Low (C:L)", "Estimated low confidentiality impact pending manual review."),
        ("Integrity", "Low (I:L)", "Estimated low integrity impact pending manual review."),
        ("Availability", "None (A:N)", "Estimated no availability impact pending manual review."),
    ],
    recording_steps=[
        "Start OBS recording.",
        "Show the plugin installed and the vulnerable code path being triggered.",
        "Show the malicious input and the server response.",
        "Stop recording.",
    ],
)


def _fill(text: str, **kwargs: str) -> str:
    """Substitute named placeholders in a template string."""
    result = text
    for key, value in kwargs.items():
        result = result.replace(f"{{{key}}}", str(value))
    return result


def _build_plugin_install(slug: str, version: str) -> list[str]:
    """
    Build step-by-step plugin installation instructions for the test environment.

    Returns a list of steps specific to the given plugin slug and version.
    """
    return [
        f"In your second terminal window, confirm you are in the test site folder: type 'pwd' and press Enter. You should see a path ending in 'wp-test'. If not, type 'cd ~/wp-test' and press Enter.",
        f"Install the specific vulnerable version of the plugin: type 'wp plugin install {slug} --version={version} --activate' and press Enter.",
        f"If the command fails because version {version} is not available on wordpress.org, install the latest version instead: type 'wp plugin install {slug} --activate' and press Enter.",
        f"Confirm the plugin installed correctly by going to http://localhost:8080/wp-admin/plugins.php in your browser. Find the plugin named '{slug}' in the list. It should have a blue 'Deactivate' link, which means it is active. If you see 'Activate' instead, click it to activate the plugin.",
        "You are now ready to test the vulnerability. Keep your test site running and move on to the reproduction steps.",
    ]


_FALLBACK_PAYOUTS: dict[str, list[tuple[int, tuple[int, int]]]] = {
    "Critical": [(80, (3000, 10000)), (60, (1500, 5000)), (0, (500,  2000))],
    "High":     [(80, (500,  3000)),  (60, (200,  1000)), (0, (50,   500))],
    "Medium":   [(80, (100,  500)),   (60, (50,   200)),  (0, (0,    100))],
}


def _estimate_payout(
    severity: str,
    confidence: int,
    payout_range: tuple[int, int] | None,
) -> tuple[int, int, str, bool]:
    """Return (low, high, label, from_platform) for one finding."""
    multipliers = {"Critical": 1.5, "High": 1.0, "Medium": 0.4, "Low": 0.1}
    conf_scale = confidence / 100

    if payout_range is not None:
        mult = multipliers.get(severity, 0.1)
        low  = round(payout_range[0] * mult * conf_scale / 50) * 50
        high = round(payout_range[1] * mult * conf_scale / 50) * 50
        label = f"${low:,} - ${high:,} (from platform)"
        return low, high, label, True

    tiers = _FALLBACK_PAYOUTS.get(severity, _FALLBACK_PAYOUTS["Medium"])
    low, high = next(bounds for threshold, bounds in tiers if confidence >= threshold)
    label = f"${low:,} - ${high:,} (est.)"
    return low, high, label, False


def analyze(
    scan_result: ScanResult,
    payout_range: tuple[int, int] | None = None,
) -> AnalysisResult:
    """
    Generate a complete manual verification walkthrough for every finding in a ScanResult.

    For each finding, produces a plain-English explanation, step-by-step reproduction
    instructions, false positive guidance, a CVSS 3.1 estimate, and a screen recording
    guide. Findings are processed in the order they appear in scan_result (confidence
    descending). Unknown pattern names fall back to a generic template.
    """
    env_setup = _ENV_SETUP_STEPS
    plugin_install = _build_plugin_install(
        scan_result.plugin_slug, scan_result.plugin_version
    )
    walkthroughs: list[VerificationWalkthrough] = []

    findings = [f for f in scan_result.findings if f.confidence >= PURSUIT_CONFIDENCE]
    for finding in findings:
        tmpl = _PATTERN_TEMPLATES.get(finding.pattern_name, _FALLBACK_TEMPLATE)

        ctx = {
            "slug": scan_result.plugin_slug,
            "version": scan_result.plugin_version,
            "file": finding.file_path,
            "line": str(finding.line_number),
            "snippet": finding.snippet.replace("|", r"\|"),
        }

        cvss = CvssEstimate(
            score=tmpl.cvss_score,
            vector=tmpl.cvss_vector,
            components=[
                CvssComponent(metric=m, value=v, explanation=e)
                for m, v, e in tmpl.cvss_components
            ],
            overall_justification=tmpl.severity_justification,
        )

        recording_guide = RecordingGuide(
            software=RECORDING_SOFTWARE,
            obs_setup=list(_OBS_SETUP_STEPS),
            before_recording=list(_BEFORE_RECORDING_STEPS),
            recording_steps=[_fill(s, **ctx) for s in tmpl.recording_steps],
            duration=RECORDING_DURATION,
            export_format=RECORDING_FORMAT,
            export_settings=RECORDING_CODEC,
        )

        pay_low, pay_high, pay_label, pay_from_platform = _estimate_payout(
            finding.severity, finding.confidence, payout_range
        )

        walkthroughs.append(
            VerificationWalkthrough(
                finding=finding,
                plain_english=_fill(tmpl.plain_english, **ctx),
                attacker_impact=tmpl.attacker_impact,
                environment_setup=list(env_setup),
                plugin_install=plugin_install,
                reproduction_steps=_build_repro_steps(
                    finding, scan_result.plugin_slug, scan_result.plugin_version
                ),
                confirmation_criteria=tmpl.confirmation_criteria,
                false_positive_checks=tmpl.false_positive_checks,
                severity_justification=tmpl.severity_justification,
                cvss=cvss,
                recording_guide=recording_guide,
                payout_low=pay_low,
                payout_high=pay_high,
                payout_estimate=pay_label,
                payout_from_platform=pay_from_platform,
            )
        )

    return AnalysisResult(
        plugin_slug=scan_result.plugin_slug,
        plugin_version=scan_result.plugin_version,
        walkthroughs=walkthroughs,
    )
