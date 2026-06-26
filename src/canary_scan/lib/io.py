"""Output writers: JSONL (default), CSV, SARIF, stdout streaming."""

from __future__ import annotations

import csv
import json
import sys
from collections.abc import Iterable
from pathlib import Path

from canary_scan.lib.config import CATEGORY_INFO, SARIF_LEVEL_MAP, TOOL_NAME, TOOL_VERSION
from canary_scan.lib.models import Finding


def write_jsonl(findings: Iterable[Finding], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8") as f:
        for finding in findings:
            f.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not path.exists():
        return findings
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            findings.append(Finding.from_dict(json.loads(line)))
    return findings


def write_csv(findings: list[Finding], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = Finding.csv_columns()
    count = 0
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=cols)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.to_csv_row())
            count += 1
    return count


def _sarif_rule(findings: list[Finding]) -> list[dict]:
    seen: dict[str, dict] = {}
    for f in findings:
        rule_id = f"canary-scan/{f.category}/{f.subcategory}" if f.subcategory else f"canary-scan/{f.category}"
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "name": f.category,
                "shortDescription": {"text": CATEGORY_INFO.get(f.category, f.category)},
                "fullDescription": {"text": f.finding},
                "helpUri": "https://github.com/psaintelligence/canary-scan#report-interpretation",
                "defaultConfiguration": {"level": SARIF_LEVEL_MAP.get(_severity_enum(f.severity), "note")},
            }
    return list(seen.values())


def _severity_enum(sev: str):
    from canary_scan.lib.config import Severity

    for s in Severity:
        if s.value == sev:
            return s
    return Severity.INFO


def write_sarif(findings: list[Finding], path: Path) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    results = []
    for f in findings:
        rule_id = f"canary-scan/{f.category}/{f.subcategory}" if f.subcategory else f"canary-scan/{f.category}"
        results.append(
            {
                "ruleId": rule_id,
                "level": SARIF_LEVEL_MAP.get(_severity_enum(f.severity), "note"),
                "message": {"text": f.finding},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file,
                                "properties": {"sha256": f.sha256},
                            },
                        },
                    }
                ],
                "partialFingerprints": {"evidence": f.evidence} if f.evidence else {},
                "properties": {
                    "bucket": f.bucket,
                    "file_type": f.file_type,
                    "stage": f.stage,
                    "subcategory": f.subcategory,
                    "tool": f.tool,
                    "confidence": f.confidence,
                    "extras": f.extras,
                },
            }
        )
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "informationUri": "https://github.com/psaintelligence/canary-scan",
                        "rules": _sarif_rule(findings),
                    },
                },
                "results": results,
            }
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    return len(results)


def write_stdout(findings: Iterable[Finding]) -> int:
    count = 0
    for finding in findings:
        sys.stdout.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
        count += 1
    sys.stdout.flush()
    return count


def write_report(
    findings: list[Finding],
    outdir: Path,
    fmt: str,
    stdout: bool = False,
) -> dict[str, int]:
    counts: dict[str, int] = {}
    if stdout:
        counts["stdout"] = write_stdout(findings)

    if fmt in ("json", "all"):
        counts["json"] = write_jsonl(findings, outdir / "canary-scan-report.json")
    if fmt in ("csv", "all"):
        counts["csv"] = write_csv(findings, outdir / "canary-scan-report.csv")
    if fmt in ("sarif", "all"):
        counts["sarif"] = write_sarif(findings, outdir / "canary-scan-report.sarif")
    return counts
