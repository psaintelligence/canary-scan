"""CLI command handler for executing a single stage of the pipeline."""

from __future__ import annotations

from pathlib import Path

import typer

from canary_scan.commands.scan import execute_pipeline
from canary_scan.lib.config import (
    DEFAULT_MAX_ARCHIVE_DEPTH,
    DEFAULT_MIN_CLUSTER_SIZE,
    DEFAULT_OUTDIR,
    DEFAULT_WORKERS,
    FormatOption,
    SeverityThreshold,
    StageName,
)


def stage(
    stage_name: StageName = typer.Argument(..., help="Stage name to run."),
    datasource: Path = typer.Argument(..., help="Path to the read-only mounted data-source directory."),
    outdir: Path = typer.Option(Path(DEFAULT_OUTDIR), "-o", "--outdir", help="Output directory."),
    fmt: FormatOption = typer.Option(
        FormatOption.json, "-f", "--format", help="Final report format (report stage only)."
    ),
    stdout: bool = typer.Option(False, "--stdout", help="Emit JSONL to stdout (report stage only)."),
    severity_threshold: SeverityThreshold = typer.Option(SeverityThreshold.info, "--severity-threshold"),
    workers: int = typer.Option(DEFAULT_WORKERS, "--workers"),
    resume: bool = typer.Option(True, "--resume/--no-resume"),
    force: bool = typer.Option(False, "--force"),
    strict_deps: bool = typer.Option(False, "--strict-deps"),
    keep_tmp: bool = typer.Option(False, "--keep-tmp"),
    crack_steg: Path | None = typer.Option(None, "--crack-steg"),
    fuzzy_cluster: bool = typer.Option(False, "--fuzzy-cluster"),
    min_cluster_size: int = typer.Option(DEFAULT_MIN_CLUSTER_SIZE, "--min-cluster-size"),
    max_archive_depth: int = typer.Option(DEFAULT_MAX_ARCHIVE_DEPTH, "--max-archive-depth"),
    enable_specialized: bool = typer.Option(False, "--enable-specialized"),
    verbose: bool = typer.Option(False, "--verbose/--quiet"),
) -> None:
    """
    Run a single stage of the pipeline.

    [bold]Pipeline Stages Available:[/bold]
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
        stages=[stage_name.value],
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
        verbose=verbose,
    )
