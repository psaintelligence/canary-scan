"""CLI command handler for checking external dependencies."""

from __future__ import annotations

import typer
from rich.console import Console

from canary_scan.lib.deps import check_dependencies, format_dep_table
from canary_scan.lib.deps import fix_hints as get_fix_hints

console = Console()


def deps(
    fix_hints: bool = typer.Option(False, "--fix-hints", help="Print install commands for missing deps."),
    enable_specialized: bool = typer.Option(False, "--enable-specialized", help="Include specialized deps."),
    strict: bool = typer.Option(False, "--strict-deps", help="Treat optional as required."),
) -> None:
    """Check and report on external binary dependencies."""
    status = check_dependencies(enable_specialized=enable_specialized, strict=strict)
    if fix_hints:
        hints = get_fix_hints(status)
        if hints:
            console.print(hints)
        else:
            console.print("[green]All dependencies found.[/green]")
        return
    console.print(format_dep_table(status))
    if status["missing_required"]:
        raise typer.Exit(2)
