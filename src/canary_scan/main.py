"""CLI main entry point for canary-scan."""

from __future__ import annotations

import typer
from rich.console import Console

from canary_scan import __version__
from canary_scan.commands.deps import deps
from canary_scan.commands.report import report
from canary_scan.commands.scan import scan
from canary_scan.commands.stage import stage
from canary_scan.lib.guide import get_guide

app = typer.Typer(
    name="canary-scan",
    help="""
Scan a document data-source for canaries, trackers, web beacons, and per-recipient fingerprints.

[bold]Pipeline Stages:[/bold]
  [bold]inventory[/bold] - Walks filesystem, hashes, identifies MIME types, and classifies files.
  [bold]metadata[/bold] - Extracts metadata via exiftool, scans for URLs/PII.
  [bold]remote-refs[/bold] - XXE, tracking links, remote template URLs.
  [bold]embedded[/bold] - Extracts nested files, image pixels, OLE/ActiveX.
  [bold]stego[/bold] - Steghide/stegseek stego carrier checks.
  [bold]uniqueness[/bold] - Near-duplicate clustering to find per-recipient canary values.
  [bold]report[/bold] - Merges stage outputs, filters by severity, formats report.
""",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"canary-scan {__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
    guide: bool = typer.Option(
        False,
        "--guide",
        is_eager=True,
        help="Print the workflow guide and exit.",
    ),
) -> None:
    """canary-scan: detect canaries and trackers in document data-sources before interaction."""
    if guide:
        console.print(get_guide())
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())


# Register commands
app.command(name="deps")(deps)
app.command(name="scan")(scan)
app.command(name="stage")(stage)
app.command(name="report")(report)


if __name__ == "__main__":
    app()
