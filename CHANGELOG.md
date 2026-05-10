# Changelog

All notable changes to this project are documented in this file.
Versions follow [Semantic Versioning](https://semver.org/).

---

## [0.1.0] - 2026-05-09

### Added

- `config.py`: named constants for tool metadata, platform URLs, confidence
  thresholds, request settings, and output directories.
- `scope.py`: scope verification against Patchstack Alliance, Wordfence
  Intelligence, HackerOne, Bugcrowd, and Intigriti. Returns a `ScopeCheck`
  with per-platform results and an overall in-scope flag.
- `scanner.py`: downloads a WordPress plugin from wordpress.org, extracts
  the zip, scans all PHP files against ten vulnerability patterns (SQL
  Injection, XSS, CSRF, File Inclusion, Object Injection, Arbitrary File
  Upload, Path Traversal, Open Redirect, SSRF, Insecure Deserialization),
  and returns ranked findings with confidence scores.
- `analyzer.py`: generates a complete manual verification walkthrough for
  each finding, including plain-English description, attacker impact,
  15-step local environment setup, plugin install steps, pattern-specific
  reproduction steps, confirmation criteria, false positive checks, severity
  justification, CVSS 3.1 estimate with component breakdown, and an OBS
  Studio screen recording guide.
- `verifier.py`: runs a nine-point pre-submission checklist on each finding
  (version recorded, confidence threshold, CVSS score, reproduction steps,
  description length, video evidence size, screenshot count, scope
  confirmation, WPScan CVE cross-reference). Returns a `VerificationResult`
  with a ready flag, blocking issues, warnings, and a `summary()` method.
- `reporter.py`: generates a structured markdown report saved to the reports
  directory. Sections: header, executive summary with risk level, one section
  per finding, and a recording guide appendix.
- `cli.py`: typer entry point (`wp-bug-hunter scan <plugin-slug>`). Options:
  `--platform`, `--skip-network`, `--output-dir`. Displays a rich summary
  table after each run.
- `README.md`: installation, usage examples, environment variables, output
  description, legal notice.
- `LEGAL.md`: permitted use, prohibited use, liability disclaimer, responsible
  disclosure guidance.
