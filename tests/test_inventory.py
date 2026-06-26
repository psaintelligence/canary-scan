"""Test inventory stage."""

from canary_scan.lib.runners import RunLogger
from canary_scan.scanners.inventory import run, sha256_file


def test_sha256_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello")
    h = sha256_file(str(f))
    assert len(h) == 64
    assert h == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_inventory_runs(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    records, findings = run(str(fixtures_dir), outdir, logger)

    assert len(records) > 0
    paths = [r.path for r in records]
    assert any("pdf_uri_canary.pdf" in p for p in paths)
    assert any("csv_formula_injection.csv" in p for p in paths)
    assert any("html_beacon.html" in p for p in paths)

    inv_path = outdir / "canary-scan-inventory.json"
    assert inv_path.exists()

    logger.close()
