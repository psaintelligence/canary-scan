"""Stage inventory: inventory — sha256, stat, file(1) mime, bucket detection."""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from canary_scan.lib.config import Bucket
from canary_scan.lib.models import FileRecord, make_info_finding
from canary_scan.lib.runners import RunLogger, safe_subprocess
from canary_scan.lib.type_detect import detect_bucket, extension_of


def sha256_file(path: str, chunk_size: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def get_mime(path: str, logger: RunLogger | None = None) -> str:
    result = safe_subprocess(["file", "-b", path], logger=logger, timeout=30)
    return result.stdout.strip() if result.returncode == 0 else ""


def scan_datasource(datasource: str) -> list[str]:
    files: list[str] = []
    for root, _dirs, names in os.walk(datasource):
        for name in names:
            files.append(os.path.join(root, name))
    return sorted(files)


def _process_file(fpath: str, enable_specialized: bool, logger: RunLogger) -> FileRecord | None:
    """Hash + classify a single file. Returns None on hash failure.

    Module-level so ProcessPoolExecutor workers can pickle it.
    """
    try:
        sha = sha256_file(fpath)
    except OSError as e:
        logger.log(f"Stage inventory: cannot hash {fpath}: {e}")
        return None
    stat = os.stat(fpath)
    mime = get_mime(fpath, logger)
    ext = extension_of(fpath)
    bucket = detect_bucket(fpath, mime, enable_specialized=enable_specialized)
    return FileRecord(
        path=fpath,
        sha256=sha,
        size=stat.st_size,
        mtime=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
        mime=mime,
        bucket=bucket.value,
        extension=ext,
    )


def run(
    datasource: str,
    outdir: Path,
    logger: RunLogger,
    enable_specialized: bool = False,
    workers: int = 4,
) -> tuple[list[FileRecord], list]:
    from concurrent.futures import ProcessPoolExecutor

    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    from canary_scan.lib.io import write_jsonl
    from canary_scan.lib.models import Finding

    all_files = scan_datasource(datasource)
    logger.log(f"Stage inventory: found {len(all_files)} files")

    records: list[FileRecord] = []
    findings: list[Finding] = []

    # Parallelise the per-file work (hash + stat + mime + bucket). Each
    # worker receives the logger (fork-inherited; RunLogger reopens in the
    # child) and the enable_specialized flag.
    if workers > 1 and len(all_files) > 1:
        with ProcessPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(_process_file, fpath, enable_specialized, logger): fpath for fpath in all_files}
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task("Building file inventory...", total=len(all_files))
                for future in futures:
                    try:
                        rec = future.result()
                    except Exception as e:
                        logger.log(f"Stage inventory: future error on {futures[future]}: {e}")
                        rec = None
                    if rec is not None:
                        records.append(rec)
                        if rec.bucket == Bucket.OTHER:
                            findings.append(
                                make_info_finding(
                                    rec,
                                    stage="inventory",
                                    message=f"No bucket-specific canary check for this file type (mime: {rec.mime})",
                                )
                            )
                    progress.advance(task)
    else:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Building file inventory...", total=len(all_files))
            for fpath in all_files:
                rec = _process_file(fpath, enable_specialized, logger)
                if rec is not None:
                    records.append(rec)
                    if rec.bucket == Bucket.OTHER:
                        findings.append(
                            make_info_finding(
                                rec,
                                stage="inventory",
                                message=f"No bucket-specific canary check for this file type (mime: {rec.mime})",
                            )
                        )
                progress.advance(task)

    write_jsonl(
        (
            Finding(
                file=r.path,
                sha256=r.sha256,
                file_type=r.extension or r.bucket,
                bucket=r.bucket,
                stage="inventory",
                category="no_bucket_check" if r.bucket == "other" else "inventory",
                subcategory="",
                finding="file inventoried",
                evidence="",
                tool="canary-scan",
                severity="info",
                confidence=0.0,
                extras=r.to_dict(),
            )
            for r in records
        ),
        outdir / "canary-scan-inventory.json",
    )
    logger.log(f"Stage inventory: wrote {len(records)} inventory records")
    return records, findings
