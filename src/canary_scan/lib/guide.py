"""Inline workflow guide printed by `canary-scan --guide`."""

from __future__ import annotations

GUIDE_TEXT = """\
canary-scan — Canary & Tracker Detection Workflow
=================================================

1. CHECK DEPENDENCIES
   canary-scan deps
   canary-scan deps --fix-hints   # prints install commands

2. RUN THE FULL SCAN (runs all pipeline stages)
   canary-scan scan /mnt/datasource
   Output is written to `.canary-scan` path by default.

3. REVIEW THE REPORT
   jq '.[] | select(.severity=="critical")' .canary-scan/canary-scan-report.json
   Severity scale: critical > high > medium > low > info
    - critical: active phone-home URL or JS that fires on open
    - high:     embedded OLE/JS objects, steg payload found
    - medium:   unique fingerprint between near-duplicates, GPS, PII
    - low:      metadata oddity, non-standard producer
    - info:     annotated, no canary confirmed

4. CHAIN INTO OTHER TOOLS
   canary-scan scan /mnt/datasource --stdout --severity-threshold critical | jq -c .
   canary-scan scan /mnt/datasource --format sarif   # for GitHub Security/DefectDojo
   canary-scan scan /mnt/datasource --format csv     # for spreadsheet triage

5. RE-RUNS
   --resume is the default: completed stages are skipped.
   Use --force to re-run all stages. Each run is appended to the
   audit trail in canary-scan-state.json (runs[] array).

PIPELINE STAGES
===============

* Inventory
  Walks the filesystem, hashes files, identifies MIME types via file(1), and
  classifies documents into analysis buckets.

* Metadata
  Extracts document metadata via exiftool and scans it for phone-home URLs,
  PII, or unique tracking/recipient identifiers.

* Remote References
  Inspects document structure and markup for external entities (XXE), tracking
  pixels, remote hyperlink relations, auto-update OLE links, or formula injections.

* Embedded Objects
  Extracts nested binaries, raster images, and hidden OLE/ActiveX elements
  using tools like pdfimages, rtfobj, and unzip.

* Steganography
  Scans images for steganographic carriers (using steghide) and runs opt-in
  passphrase brute-forcing checks (using stegseek).

* Uniqueness & Fingerprints
  Clusters near-duplicate documents and compares their internal structure/pixels
  (via qpdf, unzip-diff, compare) to identify per-recipient canary values.

* Final Report
  Merges and deduplicates findings from all stages, filters by severity,
  and emits the final report (JSON, CSV, SARIF).

Recommendations

* READ-ONLY MOUNT
  To protect source integrity and prevent accidental mutation, it is
  recommended to mount the data-source as read-only. See the README.md
  "Read-Only mount" section.

* AIR-GAP INSTALL
  For air-gapped analysis environments, download pip packages and system
  dependencies on a networked host, then transfer via USB. See the README.md
  "Air-gap install" section.
"""


def get_guide() -> str:
    return GUIDE_TEXT
