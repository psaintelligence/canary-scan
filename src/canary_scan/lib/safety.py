"""Safety checks: assert the data-source directory is mounted read-only."""

from __future__ import annotations

import subprocess

from rich.console import Console
from rich.panel import Panel

err_console = Console(stderr=True)


def check_readonly_mount(path: str) -> None:
    try:
        result = subprocess.run(
            ["findmnt", "-no", "OPTIONS", path],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        err_console.print(
            Panel(
                "[bold yellow]WARNING: 'findmnt' tool not found.[/bold yellow]\n"
                "Cannot verify if the mount is read-only.\n\n"
                "[bold white]Tip:[/bold white] Install [cyan]util-linux[/cyan] to enable mount validation checks.\n"
                "Scanning will proceed, but verify mount status manually.",
                title="[bold yellow]Safety Check Alert[/bold yellow]",
                border_style="yellow",
            )
        )
        return

    if result.returncode != 0:
        err_console.print(
            Panel(
                "[bold yellow]WARNING: Could not determine mount status.[/bold yellow]\n"
                "Mount check failed to query status.\n\n"
                "[bold white]Recommendation:[/bold white] Ensure your data source is read-only to protect evidence integrity.",
                title="[bold yellow]Safety Check Warning[/bold yellow]",
                border_style="yellow",
            )
        )
        return

    options = result.stdout.strip()
    if "ro" not in options.split(","):
        err_console.print(
            Panel(
                f"[bold red]WARNING: Writable Mount Detected[/bold red]\n"
                f"Path {path!r} is NOT mounted read-only (options: {options}).\n\n"
                "[yellow]Scanning a writable mount risks accidental data alteration or evidence contamination.[/yellow]\n"
                "[yellow]Execution continues, but mounting read-only is highly recommended.[/yellow]\n\n"
                                "[bold white]Remediation Suggestions:[/bold white]\n"
                "  [cyan]archivemount -o ro datasource.tar.gz /mnt/datasource[/cyan]\n"
                "  [cyan]mount -o remount,ro /mnt/datasource[/cyan]",
                title="[bold red]OPSEC / Integrity Alert[/bold red]",
                border_style="red",
            )
        )

