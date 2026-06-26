import datetime
import time
from unittest.mock import patch

from canary_scan.lib.models import FileRecord
from canary_scan.lib.runners import safe_subprocess
from canary_scan.lib.state import StateManager
from canary_scan.scanners.remote_refs import _read_bytes, _read_text


def test_safe_subprocess_file_not_found():
    res = safe_subprocess(["non_existent_binary_abc_123"])
    assert res.file_not_found is True
    assert res.returncode == 127
    assert "command not found" in res.stderr


def test_file_read_size_limits(tmp_path):
    large_file = tmp_path / "large.txt"
    # Create a 51 MB dummy file (50 MB is the threshold)
    with open(large_file, "wb") as f:
        f.seek(51 * 1024 * 1024 - 1)
        f.write(b"\0")

    assert large_file.stat().st_size > 50 * 1024 * 1024

    txt = _read_text(str(large_file))
    assert txt == ""

    data = _read_bytes(str(large_file))
    assert data == b""

    small_file = tmp_path / "small.txt"
    small_file.write_text("hello world")
    assert _read_text(str(small_file)) == "hello world"
    assert _read_bytes(str(small_file)) == b"hello world"


def test_stage_timing_distinct(tmp_path):
    state = StateManager(tmp_path, str(tmp_path))
    state.stage_started("inventory")

    # Fake stage_start_times to be 1 hour ago
    state._stage_start_times["inventory"] = time.time() - 3600
    state.stage_completed("inventory", 0, "dummy.json")

    status = state._state.stages["inventory"]
    assert status.started != status.finished

    started_dt = datetime.datetime.strptime(status.started, "%Y-%m-%dT%H:%M:%S")
    finished_dt = datetime.datetime.strptime(status.finished, "%Y-%m-%dT%H:%M:%S")
    assert (finished_dt - started_dt).total_seconds() >= 3500


def test_scanners_emit_info_on_exception(tmp_path):
    from canary_scan.lib.runners import RunLogger
    from canary_scan.scanners.embedded import _process_embedded_record
    from canary_scan.scanners.metadata import _process_record as _process_metadata_record
    from canary_scan.scanners.stego import _process_stego_record

    rec = FileRecord(
        path=str(tmp_path / "dummy.png"),
        sha256="abc",
        size=10,
        mtime="2026",
        mime="image/png",
        bucket="image",
        extension=".png",
    )
    logger = RunLogger(tmp_path / "test.log")

    with patch("canary_scan.scanners.embedded.route", side_effect=ValueError("embedded error")):
        findings = _process_embedded_record(rec, tmp_path, logger)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "embedded stage error: embedded error" in findings[0].finding

    with patch("canary_scan.scanners.stego.scan_image", side_effect=ValueError("stego error")):
        findings = _process_stego_record(rec, logger, None)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "stego stage error: stego error" in findings[0].finding

    with patch("canary_scan.scanners.metadata.safe_subprocess", side_effect=ValueError("metadata error")):
        path, fields, findings = _process_metadata_record(rec, logger)
        assert len(findings) == 1
        assert findings[0].severity == "info"
        assert "metadata stage error: metadata error" in findings[0].finding
