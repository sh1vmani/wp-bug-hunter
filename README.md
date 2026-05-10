# wp-bug-hunter

A command-line tool for WordPress plugin bug bounty research. It downloads a plugin
from the WordPress plugin directory, scans the PHP source for common vulnerability
patterns, generates a plain-English walkthrough for each finding, checks whether the
target is in scope on supported bug bounty platforms, cross-references known CVEs in
WPScan, runs a submission readiness checklist against your evidence folder, and writes
a structured markdown report ready to attach to a bug bounty submission.

## Requirements

- Python 3.11 or newer
- Kali Linux or any Debian-based system
- Internet access for plugin download, scope checks, and CVE lookups (can be skipped
  with `--skip-network`)

## Installation

Clone the repository and install in editable mode:

```bash
git clone https://github.com/sh1vmani/wp-bug-hunter.git
cd wp-bug-hunter
pip install -e .
```

## Usage

```bash
# Full pipeline: scope check, scan, analyze, verify, report
wp-bug-hunter scan <plugin-slug>

# Skip scope and CVE network checks (offline mode)
wp-bug-hunter scan <plugin-slug> --skip-network

# Tag the report with a platform name
wp-bug-hunter scan <plugin-slug> --platform hackerone

# Write the report to a custom directory
wp-bug-hunter scan <plugin-slug> --output-dir /tmp/reports
```

Replace `<plugin-slug>` with the plugin's slug as it appears in the WordPress plugin
directory URL. For example, the slug for
`https://wordpress.org/plugins/contact-form-7/` is `contact-form-7`.

## Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `WPSCAN_API_KEY` | No | Enables CVE cross-reference via the WPScan API. Without this key the CVE check is skipped and a warning is added to the verification result. A free API key is available at wpscan.com. |

## Output

Each run produces two things:

**Report file:** A markdown file saved to the `reports/` directory (or the path
given with `--output-dir`). The filename is `<plugin-slug>_<YYYYMMDD>.md`. It
contains an executive summary, one section per finding with full reproduction steps
and a CVSS breakdown, verification status with any blocking issues or warnings, and
a recording guide appendix.

**Evidence folder:** The verifier reads from `evidence/<plugin-slug>/` to check for
video recordings and screenshots. Create this folder and place your evidence files
there before running the tool. The tool does not create or modify evidence files.

## Legal Notice

This tool is for use only on WordPress plugins that are listed as in-scope targets
in an active, publicly accessible bug bounty program that you are authorized to
participate in. Do not use it against plugins or sites that you do not have explicit
written permission to test. Misuse may violate computer fraud laws in your
jurisdiction. The author accepts no liability for unauthorized use.

## License

Apache License 2.0. See the LICENSE file for the full text.
