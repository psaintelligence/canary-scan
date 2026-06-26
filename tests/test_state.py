"""Test state management: flock, runs[] history."""

from canary_scan.lib.state import StateManager


def test_acquire_release_lock(tmp_path):
    outdir = tmp_path / ".canary-scan"
    sm = StateManager(outdir, "/mnt/datasource")
    sm.acquire_lock()
    assert (outdir / "canary-scan.lock").exists()
    sm.release_lock()


def test_run_history_append(tmp_path):
    outdir = tmp_path / ".canary-scan"
    sm = StateManager(outdir, "/mnt/datasource")
    sm.acquire_lock()
    try:
        sm.start_run(["canary-scan", "scan", "/mnt/datasource"], ["inventory", "metadata"])
        sm.stage_completed("inventory", 0, "canary-scan-inventory.json")
        sm.finish_run(0)
    finally:
        sm.release_lock()

    sm2 = StateManager(outdir, "/mnt/datasource")
    sm2.acquire_lock()
    try:
        sm2.start_run(["canary-scan", "scan", "/mnt/datasource"], ["remote-refs"])
        sm2.finish_run(0)
        state = sm2.load()
        assert len(state.runs) == 2
        assert state.runs[0].stages_run == ["inventory", "metadata"]
        assert state.runs[1].stages_run == ["remote-refs"]
    finally:
        sm2.release_lock()


def test_stage_should_run(tmp_path):
    outdir = tmp_path / ".canary-scan"
    sm = StateManager(outdir, "/mnt/datasource")
    sm.acquire_lock()
    try:
        assert sm.stage_should_run("inventory", force=False) is True
        sm.stage_completed("inventory", 0, "canary-scan-inventory.json")
        assert sm.stage_should_run("inventory", force=False) is False
        assert sm.stage_should_run("inventory", force=True) is True
    finally:
        sm.release_lock()
