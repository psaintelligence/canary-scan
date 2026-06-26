"""Test FilterEngine, allowlist/denylist filtering, and severity calibration."""

from __future__ import annotations

import json

from canary_scan.lib.config import Severity
from canary_scan.lib.filters import FilterEngine
from canary_scan.lib.models import Finding


def test_benign_domain_calibration():
    # Verify standard benign domain is downgraded to INFO/0.2
    findings = [
        Finding(
            file="file.pdf",
            sha256="abc",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://www.w3.org/1999/xhtml",
            tool="pdf-parser",
            severity="critical",
            confidence=0.9,
        )
    ]
    engine = FilterEngine()
    evaluated = engine.evaluate(findings)
    assert len(evaluated) == 1
    assert evaluated[0].severity == Severity.INFO.value
    assert evaluated[0].confidence == 0.2


def test_custom_allowlist(tmp_path):
    allowlist_file = tmp_path / "allowlist.json"
    rules = {
        "domains": ["safe-domain.com"],
        "urls": ["http://another-safe.com/pixel.gif"],
        "files": ["/path/to/safe.pdf"],
        "metadata": {
            "creator": ["safe-creator-tool"]
        }
    }
    allowlist_file.write_text(json.dumps(rules))

    findings = [
        # Skip via domain
        Finding(
            file="f1.pdf",
            sha256="a",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://safe-domain.com/path",
            tool="pdf-parser",
            severity="critical",
            confidence=0.9,
        ),
        # Skip via URL
        Finding(
            file="f2.pdf",
            sha256="b",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://another-safe.com/pixel.gif",
            tool="pdf-parser",
            severity="critical",
            confidence=0.9,
        ),
        # Skip via file
        Finding(
            file="/path/to/safe.pdf",
            sha256="c",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://malicious.com",
            tool="pdf-parser",
            severity="critical",
            confidence=0.9,
        ),
        # Skip via metadata value
        Finding(
            file="f3.pdf",
            sha256="d",
            file_type="pdf",
            bucket="pdf",
            stage="metadata",
            category="metadata_pii",
            subcategory="creator",
            finding="Found PII",
            evidence="safe-creator-tool v1.0",
            tool="exiftool",
            severity="medium",
            confidence=0.6,
        ),
        # Keep this one
        Finding(
            file="f4.pdf",
            sha256="e",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://suspicious.com",
            tool="pdf-parser",
            severity="critical",
            confidence=0.9,
        ),
    ]

    engine = FilterEngine(allowlist_path=allowlist_file)
    evaluated = engine.evaluate(findings)
    assert len(evaluated) == 1
    assert evaluated[0].file == "f4.pdf"


def test_custom_denylist(tmp_path):
    denylist_file = tmp_path / "denylist.json"
    rules = {
        "domains": ["malicious-domain.com"],
        "urls": ["http://bad-url.com/tracker.gif"]
    }
    denylist_file.write_text(json.dumps(rules))

    findings = [
        Finding(
            file="f1.pdf",
            sha256="a",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://malicious-domain.com/path",
            tool="pdf-parser",
            severity="low",
            confidence=0.3,
        ),
        Finding(
            file="f2.pdf",
            sha256="b",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Found URL",
            evidence="http://bad-url.com/tracker.gif",
            tool="pdf-parser",
            severity="medium",
            confidence=0.5,
        ),
    ]

    engine = FilterEngine(denylist_path=denylist_file)
    evaluated = engine.evaluate(findings)
    assert len(evaluated) == 2
    assert all(f.severity == "critical" for f in evaluated)
    assert all(f.confidence == 1.0 for f in evaluated)


def test_heuristics_rare_vs_ubiquitous():
    # 1 unique url in 1 file (f1.pdf)
    # 1 ubiquitous url in 10 different files (f2..f11)
    findings = []
    findings.append(
        Finding(
            file="f1.pdf",
            sha256="a",
            file_type="pdf",
            bucket="pdf",
            stage="remote-refs",
            category="active_url",
            subcategory="uri_action",
            finding="Unique URL",
            evidence="http://unique-tracker.com/pixel",
            tool="pdf-parser",
            severity="high",
            confidence=0.8,
        )
    )
    for i in range(2, 12):
        findings.append(
            Finding(
                file=f"f{i}.pdf",
                sha256="abc",
                file_type="pdf",
                bucket="pdf",
                stage="remote-refs",
                category="active_url",
                subcategory="uri_action",
                finding="Ubiquitous URL",
                evidence="http://common-shared-asset.com/img.png",
                tool="pdf-parser",
                severity="critical",
                confidence=0.9,
            )
        )

    engine = FilterEngine()
    evaluated = engine.evaluate(findings)

    # Sort order will put critical unique first
    assert evaluated[0].evidence == "http://unique-tracker.com/pixel"
    assert evaluated[0].severity == "critical"
    assert evaluated[0].confidence == 0.9 # 0.8 + 0.1

    # Ubiquitous ones should be downgraded to medium
    ubiquitous = [f for f in evaluated if f.evidence == "http://common-shared-asset.com/img.png"]
    assert len(ubiquitous) == 10
    assert all(f.severity == "medium" for f in ubiquitous)
    assert all(f.confidence == 0.8 for f in ubiquitous) # 0.9 - 0.1
