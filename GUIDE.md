# wp-bug-hunter User Guide

## 1. What this tool does

wp-bug-hunter scans WordPress plugin source code for security vulnerabilities such as SQL injection, cross-site scripting, and broken access control. It checks each potential finding against the plugin's bug bounty scope, then filters out false positives using a verification step. At the end of a scan, you receive a markdown report containing only real, submittable findings, along with reproduction steps you can copy directly into a bug bounty submission.

---

## 2. What you need before starting

**Operating system**

Kali Linux or any Debian-based Linux system (Ubuntu, Parrot OS, and similar distributions all work).

**Python 3.11 or newer**

Check your version:

```bash
python3 --version
```

You should see output like `Python 3.11.x` or higher. If the number is lower than 3.11, upgrade Python before continuing.

**Git**

Check that Git is installed:

```bash
git --version
```

You should see output like `git version 2.x.x`. If you see "command not found", install Git with:

```bash
sudo apt install git
```

**SVN (Subversion)**

SVN is used by the tool to automatically download plugin source code from the WordPress plugin repository. The tool runs SVN for you when you start a scan, so no manual checkout is required. Install it with:

```bash
sudo apt install subversion
```

Verify it installed correctly:

```bash
svn --version
```

**A bug bounty account**

You need an active, registered account on at least one of the following platforms:

- Patchstack Alliance: https://alliance.patchstack.com
- Wordfence Intelligence: https://www.wordfence.com/threat-intel/bug-bounty-program/
- HackerOne: https://hackerone.com
- Bugcrowd: https://bugcrowd.com
- Intigriti: https://intigriti.com

**A plugin listed in scope**

Before running a scan, you must identify a specific WordPress plugin that is listed as an in-scope target on one of the platforms above. Section 4 explains how to find one.

---

## 3. Installation (one time only)

Clone the repository to your local machine:

```bash
git clone https://github.com/sh1vmani/wp-bug-hunter.git
```

Move into the project directory:

```bash
cd wp-bug-hunter
```

Install the tool and its dependencies:

```bash
pip install -e . --break-system-packages
```

Verify the installation worked:

```bash
wp-bug-hunter --help
```

You should see a list of available commands and options printed to your terminal. If you see "command not found", close and reopen your terminal and try again.

---

## 4. Finding a target plugin

1. Log in to one of the bug bounty platforms listed in section 2.
2. Browse the available programs and look for WordPress plugin targets listed as in scope.
3. Note the exact plugin name.
4. Open your browser and go to: https://wordpress.org/plugins
5. Search for the plugin by name.
6. Open the plugin's page. The URL will look like this:

```
https://wordpress.org/plugins/SLUG/
```

The slug is the last segment of the URL, between the final two slashes. For example:

```
https://wordpress.org/plugins/give/
```

The slug here is `give`.

Write down the slug. You will use it in every command from this point on.

---

## 5. How the tool downloads the plugin source code

When you run a scan, the tool automatically checks out the latest version of the plugin from the WordPress SVN repository. You do not need to run any SVN commands yourself. The download happens in a temporary directory and is cleaned up after the scan completes.

If you want to see all available versions for a plugin before scanning, you can run:

```bash
svn list https://plugins.svn.wordpress.org/SLUG/tags/
```

This prints a list of every tagged release available for that plugin. To scan a specific older version, see section 12.

---

## 6. Running a scan

All commands in this section should be run from inside the `wp-bug-hunter` directory you cloned in section 3.

**Standard scan**

This is the standard scan. Replace `SLUG` with your plugin slug and replace `patchstack` with your platform name. Accepted platform values are: `patchstack`, `wordfence`, `hackerone`, `bugcrowd`, `intigriti`.

```bash
wp-bug-hunter scan SLUG --platform patchstack
```

The tool will check scope on the platform, download the plugin source automatically, scan all PHP files, analyze and verify each finding, then save a report to `reports/SLUG_DATE.md`.

**Research mode**

To see all findings the scanner found, including those that failed verification, add `--show-all`:

```bash
wp-bug-hunter scan SLUG --platform patchstack --show-all
```

In research mode the report and summary table include every finding regardless of verification status. Failed findings are clearly marked and should not be submitted without manual confirmation. Use this mode to get a complete picture of the plugin's attack surface before deciding which findings to pursue and record evidence for.

**Offline scan (skip network checks)**

Use this if you have no internet connection or want to skip scope verification for now.

```bash
wp-bug-hunter scan SLUG --skip-network
```

**What each output line means**

| Output message | What it means |
|---|---|
| `Evidence directory created` or `Evidence directory found` | The tool created or found the folder where you will place your proof files before submitting. |
| `Scope check results per platform` | The tool has checked whether the plugin is listed as in scope on the platform you specified. |
| `Files scanned: N` | The number of PHP files the tool read through. |
| `Findings: N` | The number of potential vulnerabilities found before filtering and verification. |
| `Analyzing...` | The tool is examining a potential vulnerability in detail. |
| `Verifying...` | The tool is checking the evidence folder and applying its confidence scoring. |
| `Report saved to: reports/SLUG_DATE.md` | The scan finished. Your report is at the path shown. |
| Summary table | A table listing each finding, its severity, estimated payout, and whether it passed verification. |

---

## 7. Understanding payout estimates

The summary table shown at the end of each scan includes an `Est. Payout` column. This column shows how much a finding might be worth if submitted to the program you specified. The table is sorted from highest payout to lowest so the most valuable findings appear at the top.

**What the labels mean**

| Label | What it means |
|---|---|
| `$X - $Y (from platform)` | The payout range was fetched from the program page during the scope check. More reliable. |
| `$X - $Y (est.)` | The tool could not retrieve payout data from the platform and used general market averages based on severity and confidence. Less reliable. |

**How to use it**

Use the `Est. Payout` column to decide which findings to prioritize when recording evidence. A finding showing `$3,000 - $10,000 (from platform)` is worth significantly more time than one showing `$50 - $200 (est.)`. The executive summary section of the report also shows a total estimated payout across all verified findings.

**Important**

These are estimates only. Actual payouts depend on the program's current rates, the quality of your report, and the platform's own severity assessment. Always verify current rates on the program page before investing significant time in a finding.

---

## 8. Reading your results

**Where the report is saved**

After a scan finishes, the report is saved to:

```
reports/SLUG_DATE.md
```

For example, if you scanned the `give` plugin on May 9 2026, the file would be:

```
reports/give_20260509.md
```

Open this file in any text editor or markdown viewer.

**Executive summary**

The top of the report contains an executive summary. This section tells you how many findings were identified, how many passed verification, the overall risk level, and the total estimated payout across all verified findings.

**What each finding section contains**

- **Description:** What the vulnerability is and where in the plugin code it exists.
- **Impact:** What an attacker could do if they exploited it.
- **CVSS score:** A number from 0 to 10 that rates the severity. Higher numbers mean higher severity.
- **Reproduction steps:** The exact steps to demonstrate the vulnerability on a live site.
- **Verification status:** Whether the finding passed, failed, or has a warning.

**Verification status meanings**

| Status | What it means |
|---|---|
| `PASS` | The finding met the confidence threshold and evidence requirements. It is ready to submit. |
| `FAIL` | The finding did not meet the threshold. It may be a false positive or needs more evidence. |
| `WARN` | The finding is likely real but something is missing, such as a screenshot or recording. |

**If zero findings pass**

This is normal when scanning a plugin for the first time. Try one of the following:

- Add evidence files to the evidence directory (see section 9) and re-run the scan.
- Run with `--show-all` to see all findings and identify which ones are worth pursuing.
- Choose a different plugin from your bug bounty program's scope list.

---

## 9. Setting up evidence before verification passes

**What the evidence directory is**

When you run a scan, the tool creates a folder at:

```
evidence/SLUG/
```

This is where you place proof that you have manually verified a vulnerability yourself. Without this evidence, findings will not reach `PASS` status.

**What to put in it**

- Screen recordings in `.mp4` or `.mkv` format, minimum 5 MB each.
- Screenshots in `.png` or `.jpg` format, minimum 3 images.

**How to record your screen**

Use OBS Studio to capture your screen while reproducing the vulnerability. The report includes a recording guide with step-by-step OBS instructions.

**After adding evidence**

Run the scan again with the same command you used before:

```bash
wp-bug-hunter scan SLUG --platform patchstack
```

The verification status for findings that are backed by evidence will update to `PASS`.

---

## 10. What to do with a passing finding

Once a finding shows `PASS` status in your report, follow these steps to prepare and submit it.

1. Open the report file and find the section for that specific finding.
2. Read the reproduction steps carefully from start to finish before doing anything.
3. Open OBS Studio and start recording your screen.
4. Follow the reproduction steps exactly on a test WordPress installation.
5. Take screenshots of:
   - The HTTP request you sent (use a tool like Burp Suite or your browser's developer tools network tab).
   - The HTTP response you received.
   - The visible impact on the site (for example, a script executing, or data being returned that should be private).
6. Stop the recording and save the file.
7. Place the recording and all screenshots into `evidence/SLUG/`.
8. Run the scan again:

```bash
wp-bug-hunter scan SLUG --platform patchstack
```

9. Confirm the finding still shows `PASS`.
10. Log in to your bug bounty platform.
11. Open a new submission form.
12. Use the finding section from the report as your write-up template. Copy the description, impact, CVSS score, and reproduction steps directly into the submission form.
13. Attach your screenshots and screen recording to the submission.
14. Submit.

---

## 11. Troubleshooting

**"No findings passed verification"**

The confidence score for your findings is below the threshold, or the evidence directory is empty. Add screen recordings and screenshots to `evidence/SLUG/` and run the scan again. If the directory does not exist yet, create it:

```bash
mkdir -p evidence/SLUG
```

**"Target not confirmed in scope"**

The tool could not verify the plugin on the platform you specified. Check the platform manually to confirm the plugin is listed as in scope. If it is, run the scan with `--skip-network` to bypass the scope check and continue:

```bash
wp-bug-hunter scan SLUG --skip-network
```

**"SVN checkout failed"**

Check your internet connection. Then confirm the slug is correct by visiting this URL in your browser (replace `SLUG` with the actual slug):

```
https://wordpress.org/plugins/SLUG/
```

If the page loads and shows the plugin, the slug is correct. Try running the scan again. If SVN is not installed, install it with `sudo apt install subversion`.

**"pip install failed"**

Make sure you included the `--break-system-packages` flag:

```bash
pip install -e . --break-system-packages
```

**Scan crashes with a traceback**

Run the scan again with the `--debug` flag added to the end of your command:

```bash
wp-bug-hunter scan SLUG --debug
```

Copy the full error message and traceback that appears in the terminal and include it when asking for help.

---

## 12. Advanced: scanning a specific version or local directory

By default the tool scans the latest version of the plugin from the WordPress SVN trunk. If you need to scan an older version, check it out manually first:

```bash
svn checkout https://plugins.svn.wordpress.org/SLUG/tags/VERSION SLUG-VERSION
```

Then pass the local directory to the scanner with `--local-dir`:

```bash
wp-bug-hunter scan SLUG --local-dir ./SLUG-VERSION --platform patchstack
```

The `--local-dir` option skips the automatic SVN download and reads the plugin files from the path you provide. This is for advanced use only. In most cases the standard scan command handles everything automatically.
