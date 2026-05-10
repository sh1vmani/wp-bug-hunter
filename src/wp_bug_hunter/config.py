# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Shivamani Vastrala

TOOL_NAME = "wp-bug-hunter"
VERSION = "0.1.0"
AUTHOR = "Shivamani Vastrala"

# Bug bounty platforms supported
PLATFORMS = {
    "patchstack": "https://patchstack.com/database/",
    "wordfence": "https://www.wordfence.com/threat-intel/vulnerabilities/",
    "hackerone": "https://hackerone.com/directory/programs",
    "bugcrowd": "https://bugcrowd.com/programs",
    "intigriti": "https://app.intigriti.com/programs",
}

# WordPress plugin source
WP_PLUGIN_API = "https://api.wordpress.org/plugins/info/1.2/"
WP_PLUGIN_SVN = "https://plugins.svn.wordpress.org/"

# Vulnerability pattern confidence thresholds
HIGH_CONFIDENCE = 85
MEDIUM_CONFIDENCE = 60
LOW_CONFIDENCE = 40

# Request settings
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RATE_LIMIT_DELAY = 2

# Output settings
OUTPUT_DIR = "reports"
EVIDENCE_DIR = "evidence"
