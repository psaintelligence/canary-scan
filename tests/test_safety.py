"""Test safety (read-only mount) checks."""

from unittest.mock import MagicMock, patch

from canary_scan.lib import safety


@patch("canary_scan.lib.safety.subprocess.run")
def test_readonly_passes(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="ro,relatime\n", stderr="")
    safety.check_readonly_mount("/mnt/datasource")


@patch("canary_scan.lib.safety.subprocess.run")
def test_writable_warning(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="rw,relatime\n", stderr="")
    safety.check_readonly_mount("/mnt/datasource")


@patch("canary_scan.lib.safety.subprocess.run")
def test_findmnt_error_warning(mock_run):
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="not found\n")
    safety.check_readonly_mount("/mnt/datasource")
