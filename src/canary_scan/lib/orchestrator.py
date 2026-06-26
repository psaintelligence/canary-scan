from __future__ import annotations

import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from rich.console import Console

from canary_scan.lib.config import (
    LOG_FILE,
    STAGE_ARTEFACTS,
    STAGE_DESCRIPTIONS,
    STAGE_NAMES,
    STAGE_SHORT_NAMES,
)
from canary_scan.lib.io import read_jsonl
from canary_scan.lib.models import FileRecord
from canary_scan.lib.runners import RunLogger
from canary_scan.lib.state import StateManager

console = Console()


class PipelineContext:
    def __init__(
        self,
        state: StateManager,
        datasource: Path,
        outdir: Path,
        logger: RunLogger,
        workers: int,
        force: bool,
        resume: bool,
        args: dict[str, Any],
    ) -> None:
        self.state = state
        self.datasource = datasource
        self.outdir = outdir
        self.logger = logger
        self.workers = workers
        self.force = force
        self.resume = resume
        self.args = args
        self.inventory: list[FileRecord] = []
        self.metadata: dict[str, dict] = {}


class Stage:
    name: str
    description: str
    artefact: str

    def run(self, ctx: PipelineContext) -> None:
        raise NotImplementedError

    def skip(self, ctx: PipelineContext) -> None:
        pass


class StageRegistry:
    _stages: ClassVar[dict[str, type[Stage]]] = {}

    @classmethod
    def register(cls, name: str) -> Callable[[type[Stage]], type[Stage]]:
        def decorator(stage_cls: type[Stage]) -> type[Stage]:
            stage_cls.name = name
            stage_cls.description = STAGE_DESCRIPTIONS.get(name, "")
            stage_cls.artefact = STAGE_ARTEFACTS.get(name, "")
            cls._stages[name] = stage_cls
            return stage_cls

        return decorator

    @classmethod
    def get_stage(cls, name: str) -> type[Stage] | None:
        return cls._stages.get(name)


def _load_inventory(outdir: Path) -> list[FileRecord]:
    path = outdir / STAGE_ARTEFACTS["inventory"]
    if not path.exists():
        return []
    records: list[FileRecord] = []
    for f in read_jsonl(path):
        if f.extras:
            records.append(
                FileRecord(
                    path=f.file,
                    sha256=f.sha256,
                    size=f.extras.get("size", 0),
                    mtime=f.extras.get("mtime", ""),
                    mime=f.extras.get("mime", ""),
                    bucket=f.bucket,
                    extension=f.extras.get("extension", ""),
                )
            )
    return records


def _load_metadata(outdir: Path) -> dict[str, dict]:
    path = outdir / STAGE_ARTEFACTS["metadata"]
    if not path.exists():
        return {}
    result: dict[str, dict] = {}
    for f in read_jsonl(path):
        if f.extras:
            result[f.file] = f.extras
    return result


@StageRegistry.register("inventory")
class InventoryStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.scanners.inventory import run as run_inventory

        records, _ = run_inventory(
            ctx.datasource,
            ctx.outdir,
            ctx.logger,
            ctx.args.get("enable_specialized", False),
            ctx.workers,
        )
        ctx.inventory.extend(records)

    def skip(self, ctx: PipelineContext) -> None:
        ctx.inventory.extend(_load_inventory(ctx.outdir))


@StageRegistry.register("metadata")
class MetadataStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.scanners.metadata import run as run_metadata

        if not ctx.inventory:
            ctx.inventory.extend(_load_inventory(ctx.outdir))
        meta, _ = run_metadata(ctx.inventory, ctx.outdir, ctx.logger, ctx.workers)
        ctx.metadata.update(meta)

    def skip(self, ctx: PipelineContext) -> None:
        ctx.metadata.update(_load_metadata(ctx.outdir))


@StageRegistry.register("remote-refs")
class RemoteRefsStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.scanners.remote_refs import run as run_remote_refs

        if not ctx.inventory:
            ctx.inventory.extend(_load_inventory(ctx.outdir))
        run_remote_refs(
            ctx.inventory,
            ctx.outdir,
            ctx.logger,
            ctx.workers,
            ctx.args.get("max_archive_depth", 3),
            ctx.args.get("enable_specialized", False),
        )


@StageRegistry.register("embedded")
class EmbeddedStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.scanners.embedded import run as run_embedded

        if not ctx.inventory:
            ctx.inventory.extend(_load_inventory(ctx.outdir))
        run_embedded(ctx.inventory, ctx.outdir, ctx.logger, ctx.workers, ctx.args.get("keep_tmp", False))


@StageRegistry.register("stego")
class StegoStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.scanners.stego import run as run_stego

        if not ctx.inventory:
            ctx.inventory.extend(_load_inventory(ctx.outdir))
        run_stego(ctx.inventory, ctx.outdir, ctx.logger, ctx.args.get("crack_steg"), ctx.workers)


@StageRegistry.register("uniqueness")
class UniquenessStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.scanners.uniqueness import run as run_uniqueness

        if not ctx.inventory:
            ctx.inventory.extend(_load_inventory(ctx.outdir))
        if not ctx.metadata:
            ctx.metadata.update(_load_metadata(ctx.outdir))
        run_uniqueness(
            ctx.inventory,
            ctx.metadata,
            ctx.outdir,
            ctx.logger,
            ctx.args.get("min_cluster_size", 2),
            ctx.args.get("fuzzy_cluster", False),
            ctx.workers,
        )


@StageRegistry.register("report")
class ReportStage(Stage):
    def run(self, ctx: PipelineContext) -> None:
        from canary_scan.commands.report import run_report_logic

        run_report_logic(
            ctx.outdir,
            ctx.args.get("fmt", "json"),
            ctx.args.get("stdout", False),
            ctx.args.get("severity_threshold", "info"),
            ctx.args.get("allowlist"),
            ctx.args.get("denylist"),
        )


def _execute_stage(ctx: PipelineContext, stage: Stage) -> None:
    console.print(f"[bold cyan]Stage {stage.name}: {stage.description}[/bold cyan] running...")
    ctx.state.stage_started(stage.name)
    start = time.time()
    try:
        stage.run(ctx)
        elapsed = time.time() - start
        ctx.state.stage_completed(stage.name, 0, stage.artefact)
        console.print(f"[green]Stage {stage.name}[/green] done ({elapsed:.1f}s)")
    except Exception as e:
        elapsed = time.time() - start
        ctx.state.stage_completed(stage.name, 1, stage.artefact)
        console.print(f"[red]Stage {stage.name}[/red] ERROR after {elapsed:.1f}s: {e}")
        raise


def _skip_stage(ctx: PipelineContext, stage: Stage) -> None:
    console.print(f"[yellow]Stage {stage.name}: skipped (already completed)[/yellow]")
    ctx.logger.log(f"Stage {stage.name}: skipped (already completed)")
    stage.skip(ctx)


def run_pipeline(
    state: StateManager,
    datasource: Path,
    outdir: Path,
    stages: list[str],
    fmt: str,
    stdout: bool,
    severity_threshold: str,
    workers: int,
    resume: bool,
    force: bool,
    keep_tmp: bool,
    crack_steg: str | None,
    max_archive_depth: int,
    enable_specialized: bool,
    fuzzy_cluster: bool,
    min_cluster_size: int,
    allowlist: Path | None = None,
    denylist: Path | None = None,
    verbose: bool = False,
) -> int:
    any_error = False
    exit_code = 0
    with RunLogger(outdir / LOG_FILE) as logger:
        logger.log(f"=== canary-scan run started: stages={stages} datasource={datasource} ===")
        run_record = state.start_run(sys.argv, stages)
        _ = run_record

        ctx = PipelineContext(
            state=state,
            datasource=datasource,
            outdir=outdir,
            logger=logger,
            workers=workers,
            force=force,
            resume=resume,
            args={
                "fmt": fmt,
                "stdout": stdout,
                "severity_threshold": severity_threshold,
                "keep_tmp": keep_tmp,
                "crack_steg": crack_steg,
                "max_archive_depth": max_archive_depth,
                "enable_specialized": enable_specialized,
                "fuzzy_cluster": fuzzy_cluster,
                "min_cluster_size": min_cluster_size,
                "allowlist": allowlist,
                "denylist": denylist,
            },
        )

        try:
            for stage_name in STAGE_NAMES:
                stage_cls = StageRegistry.get_stage(stage_name)
                if not stage_cls:
                    continue
                stage = stage_cls()

                if stage_name in stages:
                    if force or not resume or state.stage_should_run(stage_name, force):
                        _execute_stage(ctx, stage)
                    else:
                        _skip_stage(ctx, stage)
                else:
                    stage.skip(ctx)

        except Exception as e:
            logger.log(f"PIPELINE ERROR: {e}")
            any_error = True
        finally:
            exit_code = 4 if any_error else 0
            state.finish_run(exit_code)
            logger.log(f"=== canary-scan run finished: exit={exit_code} ===")

    if verbose and not stdout:
        _print_summary(outdir, stages)
    return exit_code


def _print_summary(outdir: Path, stages: list[str]) -> None:
    console.print("\n[bold]Summary:[/bold]")
    for stage in stages:
        if stage == "report":
            continue
        artefact = outdir / STAGE_ARTEFACTS.get(stage, "")
        if artefact.exists():
            findings = read_jsonl(artefact)
            crit = sum(1 for f in findings if f.severity == "critical")
            high = sum(1 for f in findings if f.severity == "high")
            name = STAGE_SHORT_NAMES.get(stage, "")
            console.print(f"  Stage {stage} [{name}]: {len(findings)} findings ({crit} critical, {high} high)")
    console.print(f"\nReport: {outdir / 'canary-scan-report.json'}")
