"""Test pipeline orchestrator, including stage skipping behavior."""

from canary_scan.commands.scan import run_pipeline
from canary_scan.lib.state import StateManager


def test_pipeline_skip_completed_stages(fixtures_dir, tmp_path, capsys):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    state = StateManager(outdir, str(fixtures_dir))

    # Run inventory stage first time (should run, not skip)
    state.acquire_lock()
    try:
        exit_code = run_pipeline(
            state=state,
            datasource=str(fixtures_dir),
            outdir=outdir,
            stages=["inventory"],
            fmt="json",
            stdout=False,
            severity_threshold="info",
            workers=1,
            resume=True,
            force=False,
            keep_tmp=False,
            crack_steg=None,
            fuzzy_cluster=False,
            min_cluster_size=2,
            max_archive_depth=1,
            enable_specialized=False,
            verbose=False,
        )
    finally:
        state.release_lock()

    assert exit_code == 0
    captured_first = capsys.readouterr()
    assert "Stage inventory" in captured_first.out
    assert "skipped (already completed)" not in captured_first.out

    # Run inventory stage second time with resume=True (should skip)
    state = StateManager(outdir, str(fixtures_dir))
    state.acquire_lock()
    try:
        exit_code2 = run_pipeline(
            state=state,
            datasource=str(fixtures_dir),
            outdir=outdir,
            stages=["inventory"],
            fmt="json",
            stdout=False,
            severity_threshold="info",
            workers=1,
            resume=True,
            force=False,
            keep_tmp=False,
            crack_steg=None,
            fuzzy_cluster=False,
            min_cluster_size=2,
            max_archive_depth=1,
            enable_specialized=False,
            verbose=False,
        )
    finally:
        state.release_lock()

    assert exit_code2 == 0
    captured_second = capsys.readouterr()
    assert "Stage inventory: skipped (already completed)" in captured_second.out

    # Verify logger file content
    log_content = (outdir / "canary-scan.log").read_text()
    assert "Stage inventory: skipped (already completed)" in log_content

    # Run inventory stage third time with force=True (should run again)
    state = StateManager(outdir, str(fixtures_dir))
    state.acquire_lock()
    try:
        exit_code3 = run_pipeline(
            state=state,
            datasource=str(fixtures_dir),
            outdir=outdir,
            stages=["inventory"],
            fmt="json",
            stdout=False,
            severity_threshold="info",
            workers=1,
            resume=True,
            force=True,
            keep_tmp=False,
            crack_steg=None,
            fuzzy_cluster=False,
            min_cluster_size=2,
            max_archive_depth=1,
            enable_specialized=False,
            verbose=False,
        )
    finally:
        state.release_lock()

    assert exit_code3 == 0
    captured_third = capsys.readouterr()
    assert "Stage inventory" in captured_third.out
    assert "skipped (already completed)" not in captured_third.out
