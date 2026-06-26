"""CLI command handler for rebuilding reports from stage artifacts."""

from __future__ import annotations

from pathlib import Path

import typer

from canary_scan.lib.config import (
    DEFAULT_OUTDIR,
    SEVERITY_RANK,
    STAGE_ARTEFACTS,
    FormatOption,
    Severity,
    SeverityThreshold,
)
from canary_scan.lib.filters import FilterEngine
from canary_scan.lib.io import read_jsonl, write_report
from canary_scan.lib.models import Finding


def report(
    outdir: Path = typer.Option(
        Path(DEFAULT_OUTDIR), "-o", "--outdir", help="Output directory with existing stage artefacts."
    ),
    fmt: FormatOption = typer.Option(FormatOption.json, "-f", "--format", help="Report format."),
    stdout: bool = typer.Option(False, "--stdout", help="Emit JSONL to stdout."),
    severity_threshold: SeverityThreshold = typer.Option(SeverityThreshold.info, "--severity-threshold"),
    allowlist: Path | None = typer.Option(None, "--allowlist", help="Path to JSON or text allowlist rules."),
    denylist: Path | None = typer.Option(None, "--denylist", help="Path to JSON or text denylist rules."),
) -> None:
    """
    This command reads the intermediate artifacts from the output directory (e.g., inventory, metadata,
    remote-refs), filters findings by the severity threshold, and merges/overwrites the final report
    files (JSON, CSV, SARIF). Useful for re-rendering reports with a different format or severity threshold
    without scanning the data-source again.
    """
    run_report_logic(
        outdir=outdir,
        fmt=fmt.value,
        stdout=stdout,
        severity_threshold=severity_threshold.value,
        allowlist=allowlist,
        denylist=denylist,
    )


def run_report_logic(
    outdir: Path,
    fmt: str,
    stdout: bool,
    severity_threshold: str,
    allowlist: Path | None = None,
    denylist: Path | None = None,
) -> dict[str, int]:
    all_findings: list[Finding] = []
    for stage in ("inventory", "metadata", "remote-refs", "embedded", "stego", "uniqueness"):
        artefact = outdir / STAGE_ARTEFACTS[stage]
        all_findings.extend(read_jsonl(artefact))

    # Deduplicate findings
    deduped = _deduplicate_findings(all_findings)

    # Run the filter, calibration, and sorting engine
    engine = FilterEngine(allowlist, denylist)
    calibrated = engine.evaluate(deduped)

    filtered = _filter_by_severity(calibrated, severity_threshold)
    counts = write_report(filtered, outdir, fmt, stdout)

    if not stdout:
        print_report_summary(filtered, outdir, counts)

    return counts


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    seen: dict[tuple[str, str, str, str], Finding] = {}
    for f in findings:
        key = (f.file, f.category, f.subcategory, f.evidence)
        if key in seen:
            existing = seen[key]
            existing_rank = SEVERITY_RANK.get(Severity(existing.severity), 0)
            new_rank = SEVERITY_RANK.get(Severity(f.severity), 0)
            if new_rank > existing_rank or (new_rank == existing_rank and f.confidence > existing.confidence):
                seen[key] = f
        else:
            seen[key] = f
    return list(seen.values())


def _filter_by_severity(findings: list[Finding], threshold: str) -> list[Finding]:
    threshold_rank = SEVERITY_RANK.get(Severity(threshold), 0)
    return [f for f in findings if SEVERITY_RANK.get(Severity(f.severity), 0) >= threshold_rank]


def print_report_summary(findings: list[Finding], outdir: Path, counts: dict[str, int]) -> None:
    from rich.console import Console
    from rich.table import Table

    from canary_scan.lib.config import CATEGORY_INFO

    console = Console()

    console.print("\n[bold cyan]Canary Scan Report Summary[/bold cyan]")
    console.print("")

    # 1. Output files written
    console.print("[bold]Artifacts Written:[/bold]")
    for fmt, count in counts.items():
        if fmt == "stdout":
            continue
        ext = "json" if fmt == "json" else ("csv" if fmt == "csv" else "sarif")
        filename = f"canary-scan-report.{ext}"
        path = outdir / filename
        console.print(f"  - [green]{fmt.upper()}[/green]: {path} ({count} findings)")

    if not findings:
        console.print("\n[green]No findings detected in the data-source.[/green]\n")
        return

    severity_colors = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "blue",
        "info": "dim white",
    }

    # 2. Category Table
    console.print("\n[bold]Findings by Category:[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Severity", style="bold")
    table.add_column("Category", style="cyan")
    table.add_column("Description")
    table.add_column("Count", justify="right", style="bold green")

    # Group findings by (severity, category)
    from collections import Counter
    group_counts = Counter((f.severity, f.category) for f in findings)

    # Sort groups by severity rank (critical down to info), then category
    def sort_key(item):
        sev, cat = item[0]
        rank = SEVERITY_RANK.get(Severity(sev), 0)
        return (-rank, cat)

    sorted_groups = sorted(group_counts.items(), key=sort_key)

    for (sev, cat), count in sorted_groups:
        color = severity_colors.get(sev, "white")
        desc = CATEGORY_INFO.get(cat, "")
        table.add_row(
            f"[{color}]{sev.upper()}[/{color}]",
            cat,
            desc,
            str(count)
        )

    console.print(table)
    console.print()
