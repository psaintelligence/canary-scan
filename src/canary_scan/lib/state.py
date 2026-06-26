"""State management: state.json, runs[] audit trail, flock on outdir."""

from __future__ import annotations

import fcntl
import json
import os
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from canary_scan.lib.config import (
    LOCK_FILE,
    SCHEMA_VERSION,
    STAGE_NAMES,
    STATE_FILE,
    TOOL_NAME,
    TOOL_VERSION,
)


@dataclass
class StageStatus:
    exit_code: int = -1
    started: str = ""
    finished: str = ""
    artefact: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> StageStatus:
        import inspect

        fields = {f.name for f in inspect.signature(cls).parameters.values()}
        return cls(**{k: v for k, v in d.items() if k in fields})


@dataclass
class RunRecord:
    run_id: str
    started: str
    finished: str = ""
    exit_code: int = -1
    stages_run: list[str] = field(default_factory=list)
    cli_args: list[str] = field(default_factory=list)
    canary_scan_version: str = TOOL_VERSION
    datasource: str = ""
    outdir: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RunRecord:
        import inspect

        fields = {f.name for f in inspect.signature(cls).parameters.values()}
        return cls(**{k: v for k, v in d.items() if k in fields})


@dataclass
class State:
    schema_version: str = SCHEMA_VERSION
    tool: str = TOOL_NAME
    tool_version: str = TOOL_VERSION
    datasource: str = ""
    outdir: str = ""
    stages: dict[str, StageStatus] = field(default_factory=dict)
    runs: list[RunRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "datasource": self.datasource,
            "outdir": self.outdir,
            "stages": {k: v.to_dict() for k, v in self.stages.items()},
            "runs": [r.to_dict() for r in self.runs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> State:
        stages = {k: StageStatus.from_dict(v) for k, v in d.get("stages", {}).items()}
        runs = [RunRecord.from_dict(r) for r in d.get("runs", [])]
        return cls(
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            tool=d.get("tool", TOOL_NAME),
            tool_version=d.get("tool_version", TOOL_VERSION),
            datasource=d.get("datasource", ""),
            outdir=d.get("outdir", ""),
            stages=stages,
            runs=runs,
        )


class StateManager:
    def __init__(self, outdir: Path, datasource: str) -> None:
        self.outdir = outdir
        self.datasource = datasource
        self.state_path = outdir / STATE_FILE
        self.lock_path = outdir / LOCK_FILE
        self._lock_fh = None
        self._state: State | None = None
        self._current_run: RunRecord | None = None
        self._stage_start_times: dict[str, float] = {}

    def acquire_lock(self) -> None:
        self.outdir.mkdir(parents=True, exist_ok=True)
        self._lock_fh = open(self.lock_path, "w")
        try:
            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._lock_fh.close()
            sys.stderr.write(
                f"ERROR: outdir {str(self.outdir)!r} is locked by another active canary-scan run.\n"
                f"Lock file: {self.lock_path}\n"
            )
            sys.exit(5)
        self._lock_fh.write(f"pid={os.getpid()}\n")
        self._lock_fh.flush()

    def release_lock(self) -> None:
        if self._lock_fh:
            fcntl.flock(self._lock_fh.fileno(), fcntl.LOCK_UN)
            self._lock_fh.close()
            self._lock_fh = None

    def load(self) -> State:
        if self.state_path.exists():
            with open(self.state_path, encoding="utf-8") as f:
                data = json.load(f)
            self._state = State.from_dict(data)
        else:
            self._state = State(outdir=str(self.outdir), datasource=self.datasource)
        return self._state

    def start_run(self, cli_args: list[str], stages_to_run: list[str]) -> RunRecord:
        self.load()
        run = RunRecord(
            run_id=str(uuid.uuid4()),
            started=time.strftime("%Y-%m-%dT%H:%M:%S"),
            cli_args=cli_args,
            datasource=self.datasource,
            outdir=str(self.outdir),
            stages_run=stages_to_run,
        )
        self._current_run = run
        self._state.runs.append(run)
        self.save()
        return run

    def finish_run(self, exit_code: int) -> None:
        if self._current_run:
            self._current_run.finished = time.strftime("%Y-%m-%dT%H:%M:%S")
            self._current_run.exit_code = exit_code
        self.save()

    def stage_started(self, stage: str) -> None:
        self._stage_start_times[stage] = time.time()

    def stage_completed(self, stage: str, exit_code: int, artefact: str = "") -> None:
        if self._state is None:
            self.load()
        start_time = self._stage_start_times.get(stage)
        started_str = (
            time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(start_time))
            if start_time
            else time.strftime("%Y-%m-%dT%H:%M:%S")
        )
        self._state.stages[stage] = StageStatus(
            exit_code=exit_code,
            started=started_str,
            finished=time.strftime("%Y-%m-%dT%H:%M:%S"),
            artefact=artefact,
        )
        self.save()

    def stage_should_run(self, stage: str, force: bool) -> bool:
        if force:
            return True
        if self._state is None:
            self.load()
        status = self._state.stages.get(stage)
        if status is None or status.exit_code != 0:
            return True
        return False

    def save(self) -> None:
        if self._state is None:
            return
        self.outdir.mkdir(parents=True, exist_ok=True)
        with open(self.state_path, "w", encoding="utf-8") as f:
            json.dump(self._state.to_dict(), f, indent=2)

    def all_stages_complete(self) -> bool:
        if self._state is None:
            self.load()
        for stage in STAGE_NAMES:
            s = self._state.stages.get(stage)
            if s is None or s.exit_code != 0:
                return False
        return True
