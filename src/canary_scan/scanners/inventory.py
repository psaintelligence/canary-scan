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


def run(
    datasource: str,
    outdir: Path,
    logger: RunLogger,
    enable_specialized: bool = False,
    workers: int = 4,
) -> tuple[list[FileRecord], list]:
    from canary_scan.lib.io import write_jsonl
    from canary_scan.lib.models import Finding

    all_files = scan_datasource(datasource)
    logger.log(f"Stage inventory: found {len(all_files)} files")

    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    records: list[FileRecord] = []
    findings: list[Finding] = []

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeRemainingColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("Building file inventory...", total=len(all_files))
        for fpath in all_files:
            try:
                sha = sha256_file(fpath)
            except OSError as e:
                logger.log(f"Stage inventory: cannot hash {fpath}: {e}")
                progress.advance(task)
                continue
            stat = os.stat(fpath)
            mime = get_mime(fpath, logger)
            ext = extension_of(fpath)
            bucket = detect_bucket(fpath, mime, enable_specialized=enable_specialized)
            rec = FileRecord(
                path=fpath,
                sha256=sha,
                size=stat.st_size,
                mtime=time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stat.st_mtime)),
                mime=mime,
                bucket=bucket.value,
                extension=ext,
            )
            records.append(rec)
            if bucket == Bucket.OTHER:
                findings.append(
                    make_info_finding(
                        rec,
                        stage="inventory",
                        message=f"No bucket-specific canary check for this file type (mime: {mime})",
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
