"""Subprocess runner: safe invocation with logging."""

from __future__ import annotations

import contextlib
import fcntl
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    file_not_found: bool = False
    stdout_bytes: bytes = b""
    stderr_bytes: bytes = b""


class RunLogger:
    """Append-only logger safe for use across a ProcessPoolExecutor.

    Each worker process inherits the same log path. Workers re-open the file
    in append mode on first ``log()`` call and take an inter-process
    ``fcntl.flock`` (LOCK_EX | LOCK_NB, falling back to blocking LOCK_EX) on
    every write so concurrent appends from sibling workers do not interleave
    or corrupt lines.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self._fh = None
        self._lock = threading.Lock()

    def open(self) -> None:
        with self._lock:
            if self._fh is None:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                self._fh = open(self.log_path, "a", encoding="utf-8")

    def log(self, message: str) -> None:
        if self._fh is None:
            self.open()
        with self._lock:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            line = f"[{ts}] {message}\n"
            # Inter-process lock around the write so concurrent workers
            # appending to the same file do not interleave partial lines.
            try:
                fcntl.flock(self._fh.fileno(), fcntl.LOCK_EX)
                self._fh.write(line)
                self._fh.flush()
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(self._fh.fileno(), fcntl.LOCK_UN)

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None

    def __enter__(self) -> RunLogger:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __getstate__(self) -> dict:
        state = self.__dict__.copy()
        state["_fh"] = None
        state["_lock"] = None
        return state

    def __setstate__(self, state: dict) -> None:
        self.__dict__.update(state)
        self._lock = threading.Lock()


def safe_subprocess(
    cmd: Sequence[str],
    logger: RunLogger | None = None,
    timeout: int = 300,
    cwd: str | None = None,
    env: dict | None = None,
    stdin_data: str | None = None,
    binary: bool = False,
) -> CommandResult:
    """Run a subprocess with logging and timeout handling.

    When ``binary=True`` the stdout/stderr payloads are preserved as bytes
    in ``stdout_bytes`` / ``stderr_bytes`` and the text fields are set to
    empty strings. This is required for commands whose output is itself
    binary data (e.g. ``exiftool -b -ThumbnailImage``); decoding such output
    as UTF-8 silently corrupts the bytes.
    """
    cmd_str = " ".join(cmd)
    if logger:
        logger.log(f"RUN: {cmd_str}")

    try:
        proc = subprocess.run(
            list(cmd),
            capture_output=True,
            text=not binary,
            timeout=timeout,
            cwd=cwd,
            env=env,
            input=stdin_data,
        )
        if binary:
            stdout_b = proc.stdout or b""
            stderr_b = proc.stderr or b""
            if logger:
                logger.log(f"RC={proc.returncode}")
                logger.log(f"STDOUT[binary]: {len(stdout_b)} bytes")
                if stderr_b:
                    logger.log(f"STDERR[binary]: {len(stderr_b)} bytes")
            return CommandResult(
                returncode=proc.returncode,
                stdout="",
                stderr="",
                stdout_bytes=stdout_b,
                stderr_bytes=stderr_b,
            )
        if logger:
            logger.log(f"RC={proc.returncode}")
            if proc.stdout:
                logger.log(f"STDOUT[0:2000]: {proc.stdout[:2000]}")
            if proc.stderr:
                logger.log(f"STDERR[0:2000]: {proc.stderr[:2000]}")
        return CommandResult(returncode=proc.returncode, stdout=proc.stdout, stderr=proc.stderr)
    except subprocess.TimeoutExpired as e:
        if logger:
            logger.log(f"TIMEOUT after {timeout}s")
        return CommandResult(returncode=-1, stdout=e.stdout or "", stderr=e.stderr or "", timed_out=True)
    except FileNotFoundError:
        if logger:
            logger.log(f"NOT FOUND: {cmd[0]}")
        return CommandResult(
            returncode=127,
            stdout="",
            stderr=f"{cmd[0]}: command not found",
            file_not_found=True,
        )
