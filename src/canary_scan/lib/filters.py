"""Filtering, severity calibration, allowlist/denylist, and confidence score utilization."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from canary_scan.lib.config import Severity
from canary_scan.lib.models import Finding

BENIGN_DOMAINS = {
    "w3.org",
    "xmlsoap.org",
    "openxmlformats.org",
    "oasis-open.org",
    "purl.org",
    "ietf.org",
    "schema.org",
    "adobe.com",
    "microsoft.com",
    "windows.com",
    "google.com",
    "googleapis.com",
    "apple.com",
    "oracle.com",
    "mozilla.org",
    "xml.org",
    "w3schools.com",
    "github.com",
}

SEVERITY_RANK_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_SORT_KEY = {s: i for i, s in enumerate(SEVERITY_RANK_ORDER)}


def _get_domain(url: str) -> str:
    try:
        # Strip protocols not handled cleanly by urlparse
        clean_url = url
        if url.lower().startswith("ftp://"):
            clean_url = url[6:]
        elif url.startswith("\\\\"):
            clean_url = url[2:].replace("\\", "/")
        parsed = urlparse(clean_url)
        netloc = parsed.netloc or parsed.path
        return netloc.split(":")[0].lower()
    except Exception:
        return url.lower()


def _domain_match(domain: str, patterns: set[str]) -> bool:
    if not domain:
        return False
    if domain in patterns:
        return True
    parts = domain.split(".")
    for i in range(len(parts)):
        parent = ".".join(parts[i:])
        if parent in patterns or f"*.{parent}" in patterns:
            return True
    return False


class FilterEngine:
    def __init__(self, allowlist_path: Path | None = None, denylist_path: Path | None = None) -> None:
        self.allowlist_domains: set[str] = set()
        self.allowlist_urls: set[str] = set()
        self.allowlist_metadata: dict[str, list[str]] = {}
        self.allowlist_files: set[str] = set()

        self.denylist_domains: set[str] = set()
        self.denylist_urls: set[str] = set()
        self.denylist_metadata: dict[str, list[str]] = {}
        self.denylist_files: set[str] = set()

        self._load_rules(allowlist_path, is_allow=True)
        self._load_rules(denylist_path, is_allow=False)

    def _load_rules(self, path: Path | None, is_allow: bool) -> None:
        if not path or not path.exists():
            return
        try:
            if path.suffix == ".json":
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    domains = set(data.get("domains", []))
                    urls = set(data.get("urls", []))
                    metadata = data.get("metadata", {})
                    files = set(data.get("files", []))

                    if is_allow:
                        self.allowlist_domains.update(domains)
                        self.allowlist_urls.update(urls)
                        self.allowlist_metadata.update(metadata)
                        self.allowlist_files.update(files)
                    else:
                        self.denylist_domains.update(domains)
                        self.denylist_urls.update(urls)
                        self.denylist_metadata.update(metadata)
                        self.denylist_files.update(files)
                elif isinstance(data, list):
                    if is_allow:
                        self.allowlist_domains.update(data)
                    else:
                        self.denylist_domains.update(data)
            else:
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            if is_allow:
                                self.allowlist_domains.add(line)
                            else:
                                self.denylist_domains.add(line)
        except Exception:
            pass

    def evaluate(self, findings: list[Finding]) -> list[Finding]:
        # Count unique files per domain to assess uniqueness
        domain_to_files: dict[str, set[str]] = defaultdict(set)
        all_files: set[str] = set()

        for f in findings:
            all_files.add(f.file)
            if f.category in ("active_url", "tracking_pixel") and f.evidence:
                domain = _get_domain(f.evidence)
                domain_to_files[domain].add(f.file)

        evaluated: list[Finding] = []

        for f in findings:
            # 1. Allowlist suppression
            if f.file in self.allowlist_files:
                continue
            if f.category in ("active_url", "tracking_pixel") and f.evidence:
                if f.evidence in self.allowlist_urls:
                    continue
                domain = _get_domain(f.evidence)
                if _domain_match(domain, self.allowlist_domains):
                    continue
            if f.category.startswith("metadata_") and f.subcategory in self.allowlist_metadata:
                allowed_vals = self.allowlist_metadata[f.subcategory]
                if any(val in f.evidence for val in allowed_vals):
                    continue

            # 2. Denylist elevation
            is_denied = False
            if f.file in self.denylist_files:
                is_denied = True
            elif f.category in ("active_url", "tracking_pixel") and f.evidence:
                if f.evidence in self.denylist_urls:
                    is_denied = True
                else:
                    domain = _get_domain(f.evidence)
                    if _domain_match(domain, self.denylist_domains):
                        is_denied = True

            if is_denied:
                f.severity = Severity.CRITICAL.value
                f.confidence = 1.0
                evaluated.append(f)
                continue

            # 3. Severity Calibration and Uniqueness Heuristics
            if f.category in ("active_url", "tracking_pixel") and f.evidence:
                domain = _get_domain(f.evidence)
                # Check for standard benign domains
                if _domain_match(domain, BENIGN_DOMAINS):
                    f.severity = Severity.INFO.value
                    f.confidence = 0.2
                else:
                    # Assess uniqueness based on unique file count
                    num_files = len(domain_to_files[domain])
                    if num_files == 1:
                        f.severity = Severity.CRITICAL.value
                        f.confidence = min(1.0, f.confidence + 0.1)
                    elif num_files > 20:
                        f.severity = Severity.LOW.value
                        f.confidence = max(0.3, f.confidence - 0.2)
                    elif num_files > 5:
                        f.severity = Severity.MEDIUM.value
                        f.confidence = max(0.5, f.confidence - 0.1)

            evaluated.append(f)

        # 4. Sorting: Severity rank first, then confidence descending
        evaluated.sort(key=lambda x: (SEVERITY_SORT_KEY.get(x.severity, 99), -x.confidence))
        return evaluated
