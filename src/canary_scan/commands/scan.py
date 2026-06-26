"""CLI command handler for scanning dumps and running the orchestrator."""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console

from canary_scan.lib.config import (
    DEFAULT_MAX_ARCHIVE_DEPTH,
    DEFAULT_MIN_CLUSTER_SIZE,
    DEFAULT_OUTDIR,
    DEFAULT_WORKERS,
    STAGE_NAMES,
    FormatOption,
    SeverityThreshold,
)
from canary_scan.lib.deps import assert_required_deps, check_dependencies
from canary_scan.lib.orchestrator import run_pipeline
from canary_scan.lib.safety import check_readonly_mount
from canary_scan.lib.state import StateManager

console = Console()


def scan(
    datasource: Path = typer.Argument(..., help="Path to the read-only mounted data-source directory."),
    outdir: Path = typer.Option(Path(DEFAULT_OUTDIR), "-o", "--outdir", help="Output directory."),
    fmt: FormatOption = typer.Option(FormatOption.json, "-f", "--format", help="Final report format."),
    stdout: bool = typer.Option(False, "--stdout", help="Emit JSONL to stdout."),
    severity_threshold: SeverityThreshold = typer.Option(
        SeverityThreshold.info,
        "--severity-threshold",
        help="Only emit findings at or above this severity.",
    ),
    workers: int = typer.Option(DEFAULT_WORKERS, "--workers", help="Parallel worker count."),
    resume: bool = typer.Option(True, "--resume/--no-resume", help="Skip completed stages (default)."),
    force: bool = typer.Option(False, "--force", help="Re-run all stages."),
    strict_deps: bool = typer.Option(False, "--strict-deps", help="Treat missing optional deps as fatal."),
    keep_tmp: bool = typer.Option(False, "--keep-tmp", help="Retain temp extraction directory."),
    crack_steg: Path | None = typer.Option(
        None,
        "--crack-steg",
        help="Wordlist path for opt-in stegseek cracking (stego stage).",
    ),
    fuzzy_cluster: bool = typer.Option(
        False, "--fuzzy-cluster", help="Allow producer/creator version drift in uniqueness stage."
    ),
    min_cluster_size: int = typer.Option(
        DEFAULT_MIN_CLUSTER_SIZE, "--min-cluster-size", help="Minimum cluster size for near-duplicate analysis."
    ),
    max_archive_depth: int = typer.Option(
        DEFAULT_MAX_ARCHIVE_DEPTH, "--max-archive-depth", help="Maximum nested archive recursion depth."
    ),
    enable_specialized: bool = typer.Option(
        False, "--enable-specialized", help="Enable Tier 3 specialized file types."
    ),
    allowlist: Path | None = typer.Option(None, "--allowlist", help="Path to JSON or text allowlist rules."),
    denylist: Path | None = typer.Option(None, "--denylist", help="Path to JSON or text denylist rules."),
    verbose: bool = typer.Option(False, "--verbose/--quiet", help="Verbose or quiet output."),
) -> None:
    """
    Run the full canary-scan pipeline.

    [bold]Pipeline Stages Run in Sequence:[/bold]
      [bold]inventory[/bold] - Walks filesystem, hashes, identifies MIME types, and classifies files.
      [bold]metadata[/bold] - Extracts metadata via exiftool, scans for URLs/PII.
      [bold]remote-refs[/bold] - XXE, tracking links, remote template URLs.
      [bold]embedded[/bold] - Extracts nested files, image pixels, OLE/ActiveX.
      [bold]stego[/bold] - Steghide/stegseek stego carrier checks.
      [bold]uniqueness[/bold] - Near-duplicate clustering to find per-recipient canary values.
      [bold]report[/bold] - Merges stage outputs, filters by severity, formats report.
    """
    execute_pipeline(
        datasource=str(datasource),
        outdir=outdir,
        stages=STAGE_NAMES,
        fmt=fmt.value,
        stdout=stdout,
        severity_threshold=severity_threshold.value,
        workers=workers,
        resume=resume,
        force=force,
        strict_deps=strict_deps,
        keep_tmp=keep_tmp,
        crack_steg=str(crack_steg) if crack_steg else None,
        fuzzy_cluster=fuzzy_cluster,
        min_cluster_size=min_cluster_size,
        max_archive_depth=max_archive_depth,
        enable_specialized=enable_specialized,
        allowlist=allowlist,
        denylist=denylist,
        verbose=verbose,
    )


def execute_pipeline(
    datasource: str,
    outdir: Path,
    stages: list[str],
    fmt: str,
    stdout: bool,
    severity_threshold: str,
    workers: int,
    resume: bool,
    force: bool,
    strict_deps: bool,
    keep_tmp: bool,
    crack_steg: str | None,
    fuzzy_cluster: bool,
    min_cluster_size: int,
    max_archive_depth: int,
    enable_specialized: bool,
    allowlist: Path | None = None,
    denylist: Path | None = None,
    verbose: bool = False,
) -> None:
    check_readonly_mount(datasource)
    status = check_dependencies(enable_specialized=enable_specialized, strict=strict_deps)
    assert_required_deps(status)

    state = StateManager(outdir, datasource)
    state.acquire_lock()
    try:
        exit_code = run_pipeline(
            state=state,
            datasource=Path(datasource),
            outdir=outdir,
            stages=stages,
            fmt=fmt,
            stdout=stdout,
            severity_threshold=severity_threshold,
            workers=workers,
            resume=resume,
            force=force,
            keep_tmp=keep_tmp,
            crack_steg=crack_steg,
            max_archive_depth=max_archive_depth,
            enable_specialized=enable_specialized,
            fuzzy_cluster=fuzzy_cluster,
            min_cluster_size=min_cluster_size,
            allowlist=allowlist,
            denylist=denylist,
            verbose=verbose,
        )
        if exit_code != 0:
            raise typer.Exit(exit_code)
    finally:
        state.release_lock()
