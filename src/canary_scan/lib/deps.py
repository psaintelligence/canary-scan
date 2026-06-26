"""Dependency checking: verify required/optional binaries exist before running."""

from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass
from typing import TYPE_CHECKING

from canary_scan.lib.config import DEPS, SPECIALIZED_DEPS

if TYPE_CHECKING:
    from rich.table import Table


@dataclass
class DepStatus:
    name: str
    tier: str
    install_hint: str
    binary: str
    found: bool
    purpose: str


def get_local_manager() -> tuple[str, str]:
    """Detect local package manager and type.

    Returns (manager, manager_type). Default to ('apt', 'apt') if none detected.
    """
    import shutil

    if shutil.which("apt-get") or shutil.which("apt-cache"):
        return "apt", "apt"
    if shutil.which("dnf"):
        return "dnf", "rpm"
    if shutil.which("yum"):
        return "yum", "rpm"
    if shutil.which("apk"):
        return "apk", "apk"
    return "apt", "apt"


def resolve_install_hint(install_hint: str) -> str:
    """Resolve package name and tag in install_hint to match local package manager."""
    tag, val = parse_hint(install_hint)
    system_tags = {"apt|rpm|apk", "apt|rpm", "apt", "rpm", "apk"}
    if tag in system_tags:
        from canary_scan.lib.config import PACKAGE_MAPPINGS

        manager, mgr_type = get_local_manager()
        if val in PACKAGE_MAPPINGS:
            resolved = PACKAGE_MAPPINGS[val].get(mgr_type, val)
            if resolved.startswith("["):
                return resolved
            return f"[{mgr_type}] {resolved}"
        return f"[{mgr_type}] {val}"
    return install_hint


def check_dependencies(enable_specialized: bool = False, strict: bool = False) -> dict[str, list[DepStatus]]:
    missing_required: list[DepStatus] = []
    missing_optional: list[DepStatus] = []
    found: list[DepStatus] = []

    all_deps = dict(DEPS)
    if enable_specialized:
        all_deps.update(SPECIALIZED_DEPS)

    python_modules = {
        "python-liblnk": "pylnk",
        "extract_msg": "extract_msg",
        "peepdf": "peepdf",
        "pyOneNote": "pyOneNote",
        "oletools": "oletools",
    }

    for name, (tier, install_hint, binary, purpose) in all_deps.items():
        is_found = False
        if tier == "bundled":
            try:
                import importlib.util

                module_name = f"canary_scan.bundled.{binary.replace('.py', '').replace('-', '_')}"
                if importlib.util.find_spec(module_name) is not None:
                    is_found = True
            except (ImportError, ValueError):
                pass
        elif shutil.which(binary) or shutil.which(name):
            is_found = True
        else:
            module_name = python_modules.get(name)
            if module_name:
                try:
                    import importlib.util

                    if importlib.util.find_spec(module_name) is not None:
                        is_found = True
                except (ImportError, ValueError):
                    pass

        resolved_hint = resolve_install_hint(install_hint)
        status = DepStatus(
            name=name, tier=tier, install_hint=resolved_hint, binary=binary, found=is_found, purpose=purpose
        )
        if status.found:
            found.append(status)
        else:
            if tier in ("required", "bundled") or strict:
                missing_required.append(status)
            else:
                missing_optional.append(status)

    return {"found": found, "missing_required": missing_required, "missing_optional": missing_optional}


def format_hint_rich(install_hint: str) -> str:
    """Format install hint for Rich Console with color-differentiated tag at the end."""
    from rich.markup import escape

    tag, val = parse_hint(install_hint)
    if tag == "other":
        return escape(install_hint)

    tag_colors = {
        "pip": "yellow",
        "apt|rpm|apk": "cyan",
        "apt|rpm": "cyan",
        "build": "magenta",
        "github": "blue",
        "bundled": "dim",
    }
    color = tag_colors.get(tag, "white")

    escaped_val = escape(val)
    escaped_tag = escape(f"[{tag}]")

    return f"[bold white]{escaped_val}[/bold white] [{color}]{escaped_tag}[/{color}]"


def format_dep_table(status: dict[str, list[DepStatus]]) -> Table:
    from rich.table import Table

    table = Table(title="Dependency Status")
    table.add_column("Name", style="cyan")
    table.add_column("Tier")
    table.add_column("Binary", style="magenta")
    table.add_column("Purpose", style="dim")
    table.add_column("Status")
    table.add_column("Install Hint")

    def format_tier(tier: str) -> str:
        if tier == "required":
            return "[bold white]required[/bold white]"
        elif tier == "bundled":
            return "[dim white]bundled[/dim white]"
        return "[dim]optional[/dim]"

    for s in status["found"]:
        table.add_row(
            s.name, format_tier(s.tier), s.binary, s.purpose, "[green]OK[/green]", format_hint_rich(s.install_hint)
        )
    for s in status["missing_required"]:
        table.add_row(
            s.name,
            format_tier(s.tier),
            s.binary,
            s.purpose,
            "[bold red]MISSING[/bold red]",
            format_hint_rich(s.install_hint),
        )
    for s in status["missing_optional"]:
        table.add_row(
            s.name,
            format_tier(s.tier),
            s.binary,
            s.purpose,
            "[yellow]missing[/yellow]",
            format_hint_rich(s.install_hint),
        )
    return table


def parse_hint(install_hint: str) -> tuple[str, str]:
    """Parse tag and package/instruction from install_hint.

    Returns (tag, package/instruction).
    If no tag, uses heuristics to infer tag.
    """
    install_hint = install_hint.strip()
    if install_hint.startswith("[") and "]" in install_hint:
        tag_part, remainder = install_hint.split("]", 1)
        tag = tag_part[1:].strip()
        return tag, remainder.strip()

    # Fallback/heuristics for backward compatibility
    if "pip install" in install_hint:
        pkg = install_hint.replace("pip install", "").strip()
        return "pip", pkg
    if "gem install" in install_hint:
        pkg = install_hint.replace("gem install", "").strip()
        return "gem", pkg
    if install_hint.startswith(
        (
            "lib",
            "python3",
            "qpdf",
            "poppler",
            "mupdf",
            "ripgrep",
            "unzip",
            "p7zip",
            "unrar",
            "imagemagick",
            "steghide",
            "pngcheck",
            "ffmpeg",
            "jq",
        )
    ):
        return "apt|rpm|apk", install_hint

    # Check for other known keywords
    if "build" in install_hint:
        return "build", install_hint
    if "github" in install_hint:
        return "github", install_hint

    return "other", install_hint


def fix_hints(status: dict[str, list[DepStatus]]) -> str:
    hints = []
    missing = status["missing_required"] + status["missing_optional"]

    apt_pkgs = set()
    rpm_pkgs = set()
    apk_pkgs = set()
    pip_pkgs = set()
    gem_pkgs = set()
    build_hints = set()
    github_hints = set()
    other_hints = set()

    for s in missing:
        tag, val = parse_hint(s.install_hint)
        if tag == "apt":
            apt_pkgs.add(val)
        elif tag == "rpm":
            rpm_pkgs.add(val)
        elif tag == "apk":
            apk_pkgs.add(val)
        elif tag in ("apt|rpm", "apt|rpm|apk"):
            _, mgr_type = get_local_manager()
            if mgr_type == "apt":
                apt_pkgs.add(val)
            elif mgr_type == "rpm":
                rpm_pkgs.add(val)
            elif mgr_type == "apk":
                apk_pkgs.add(val)
        elif tag == "pip":
            pip_pkgs.add(val)
        elif tag == "gem":
            gem_pkgs.add(val)
        elif tag == "build":
            build_hints.add(val)
        elif tag == "github":
            github_hints.add(val)
        else:
            other_hints.add(val)

    if apt_pkgs:
        hints.append("sudo apt install " + " ".join(sorted(apt_pkgs)))
    if rpm_pkgs:
        manager, _ = get_local_manager()
        install_cmd = "sudo dnf install" if manager == "dnf" else "sudo yum install"
        hints.append(install_cmd + " " + " ".join(sorted(rpm_pkgs)))
    if apk_pkgs:
        hints.append("apk add " + " ".join(sorted(apk_pkgs)))
    if pip_pkgs:
        hints.append("pip install " + " ".join(sorted(pip_pkgs)))
    if gem_pkgs:
        for gem in sorted(gem_pkgs):
            hints.append(f"# gem install {gem} (see project docs)")
    if build_hints:
        for b in sorted(build_hints):
            hints.append(f"# {b} (see project docs)")
    if github_hints:
        for g in sorted(github_hints):
            hints.append(f"# {g} (see project docs)")
    if other_hints:
        for o in sorted(other_hints):
            hints.append(f"# {o} (see project docs)")

    return "\n".join(hints)


def assert_required_deps(status: dict[str, list[DepStatus]]) -> None:
    if status["missing_required"]:
        sys.stderr.write("\nMissing required dependencies:\n")
        for s in status["missing_required"]:
            sys.stderr.write(f"  - {s.name} (install: {s.install_hint})\n")
        sys.stderr.write("\nRun `canary-scan deps --fix-hints` for install commands.\n")
        sys.exit(2)
