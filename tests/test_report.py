"""Test report stage."""

import json

from canary_scan.commands.report import run_report_logic as run
from canary_scan.lib.runners import RunLogger


def test_report_json(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    from canary_scan.scanners.inventory import run as run_a
    from canary_scan.scanners.remote_refs import run as run_c

    records, _ = run_a(str(fixtures_dir), outdir, logger)
    run_c(records, outdir, logger, max_archive_depth=3)

    counts = run(outdir, fmt="json", stdout=False, severity_threshold="info")

    assert "json" in counts
    report_path = outdir / "canary-scan-report.json"
    assert report_path.exists()

    lines = report_path.read_text().strip().split("\n")
    assert len(lines) > 0
    first = json.loads(lines[0])
    assert "file" in first
    assert "severity" in first
    assert "category" in first
    logger.close()


def test_report_csv(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    from canary_scan.scanners.inventory import run as run_a
    from canary_scan.scanners.remote_refs import run as run_c

    records, _ = run_a(str(fixtures_dir), outdir, logger)
    run_c(records, outdir, logger, max_archive_depth=3)

    counts = run(outdir, fmt="csv", stdout=False, severity_threshold="info")

    assert "csv" in counts
    report_path = outdir / "canary-scan-report.csv"
    assert report_path.exists()
    lines = report_path.read_text().strip().split("\n")
    assert len(lines) > 1
    assert "extras_json" in lines[0]
    logger.close()


def test_report_sarif(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    from canary_scan.scanners.inventory import run as run_a
    from canary_scan.scanners.remote_refs import run as run_c

    records, _ = run_a(str(fixtures_dir), outdir, logger)
    run_c(records, outdir, logger, max_archive_depth=3)

    counts = run(outdir, fmt="sarif", stdout=False, severity_threshold="info")

    assert "sarif" in counts
    report_path = outdir / "canary-scan-report.sarif"
    assert report_path.exists()
    sarif = json.loads(report_path.read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "canary-scan"
    logger.close()


def test_report_all(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    from canary_scan.scanners.inventory import run as run_a
    from canary_scan.scanners.remote_refs import run as run_c

    records, _ = run_a(str(fixtures_dir), outdir, logger)
    run_c(records, outdir, logger, max_archive_depth=3)

    counts = run(outdir, fmt="all", stdout=False, severity_threshold="info")

    assert "json" in counts
    assert "csv" in counts
    assert "sarif" in counts
    logger.close()


def test_findings_deduplication():
    from canary_scan.commands.report import _deduplicate_findings
    from canary_scan.lib.models import Finding

    f1 = Finding(
        file="file.txt",
        sha256="123",
        file_type="txt",
        bucket="other",
        stage="metadata",
        category="active_url",
        subcategory="hyperlink",
        finding="URL found",
        evidence="http://example.com",
        tool="test",
        severity="medium",
        confidence=0.7,
    )

    # exact duplicate but higher severity/confidence
    f2 = Finding(
        file="file.txt",
        sha256="123",
        file_type="txt",
        bucket="other",
        stage="remote-refs",
        category="active_url",
        subcategory="hyperlink",
        finding="URL found",
        evidence="http://example.com",
        tool="test",
        severity="critical",
        confidence=0.9,
    )

    # same signature but lower severity (should be discarded)
    f3 = Finding(
        file="file.txt",
        sha256="123",
        file_type="txt",
        bucket="other",
        stage="embedded",
        category="active_url",
        subcategory="hyperlink",
        finding="URL found",
        evidence="http://example.com",
        tool="test",
        severity="low",
        confidence=0.5,
    )

    deduped = _deduplicate_findings([f1, f2, f3])
    assert len(deduped) == 1
    assert deduped[0].severity == "critical"
