"""Test io module: JSONL, CSV, SARIF writers."""

import json

from canary_scan.lib.io import read_jsonl, write_csv, write_jsonl, write_sarif, write_stdout
from canary_scan.lib.models import Finding


def make_finding():
    return Finding(
        file="/mnt/datasource/test.pdf",
        sha256="abc123",
        file_type=".pdf",
        bucket="pdf",
        stage="remote-refs",
        category="active_url",
        subcategory="uri_action",
        finding="test finding",
        evidence="https://example.com",
        tool="pdfid",
        severity="critical",
        confidence=0.9,
        extras={"object_id": "12 0 R"},
    )


def test_write_read_jsonl(tmp_path):
    path = tmp_path / "test.json"
    findings = [make_finding(), make_finding()]
    count = write_jsonl(findings, path)
    assert count == 2

    loaded = read_jsonl(path)
    assert len(loaded) == 2
    assert loaded[0].category == "active_url"
    assert loaded[0].severity == "critical"


def test_write_csv(tmp_path):
    path = tmp_path / "test.csv"
    findings = [make_finding()]
    count = write_csv(findings, path)
    assert count == 1

    lines = path.read_text().strip().split("\n")
    assert "extras_json" in lines[0]
    assert len(lines) == 2


def test_write_sarif(tmp_path):
    path = tmp_path / "test.sarif"
    findings = [make_finding()]
    count = write_sarif(findings, path)
    assert count == 1

    sarif = json.loads(path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "canary-scan"
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "error"
    assert result["ruleId"] == "canary-scan/active_url/uri_action"


def test_write_stdout(capsys):
    findings = [make_finding()]
    count = write_stdout(findings)
    assert count == 1
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 1
    d = json.loads(lines[0])
    assert d["category"] == "active_url"
