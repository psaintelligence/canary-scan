"""Pytest fixtures for canary-scan tests."""

import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def have_binary(name: str) -> bool:
    return shutil.which(name) is not None


@pytest.fixture
def fixtures_dir():
    return FIXTURES_DIR


@pytest.fixture
def tmp_outdir(tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    return outdir


@pytest.fixture
def require_binary():
    """Factory: skip test if binary not installed."""

    def _check(name):
        if not have_binary(name):
            pytest.skip(f"{name} not installed")

    return _check


def ensure_fixtures():
    """Generate test fixtures if not present."""
    gen_script = Path(__file__).parent / "generate_fixtures.py"
    if gen_script.exists():
        subprocess.run(
            ["python3", str(gen_script), str(FIXTURES_DIR)],
            capture_output=True,
            timeout=60,
        )


@pytest.fixture(scope="session", autouse=True)
def generate_fixtures_session():
    ensure_fixtures()
