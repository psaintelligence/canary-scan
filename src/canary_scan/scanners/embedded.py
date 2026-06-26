"""Stage embedded: embedded object extraction — pdfimages, rtfobj, unzip OOXML parts, oleobj."""

from __future__ import annotations

import hashlib
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from canary_scan.lib.config import Bucket, Severity
from canary_scan.lib.io import write_jsonl
from canary_scan.lib.models import FileRecord, Finding, make_info_finding
from canary_scan.lib.runners import RunLogger, safe_subprocess


def _process_embedded_record(rec: FileRecord, extract_dir: Path, logger: RunLogger) -> list[Finding]:
    bucket = Bucket(rec.bucket)
    try:
        return route(rec, bucket, extract_dir, logger)
    except Exception as e:
        logger.log(f"Stage embedded: error on {rec.path}: {e}")
        return [make_info_finding(rec, "embedded", f"embedded stage error: {e}")]


def run(
    records: list[FileRecord],
    outdir: Path,
    logger: RunLogger,
    workers: int = 4,
    keep_tmp: bool = False,
) -> list[Finding]:
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    findings: list[Finding] = []
    extract_dir = outdir / "canary-scan-embedded"
    extract_dir.mkdir(parents=True, exist_ok=True)

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_process_embedded_record, rec, extract_dir, logger) for rec in records]
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Extracting embedded objects...", total=len(records))
            for future in futures:
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logger.log(f"Stage embedded: future error: {e}")
                progress.advance(task)

    write_jsonl(findings, outdir / "canary-scan-embedded.json")
    logger.log(f"Stage embedded: {len(findings)} embedded-object findings")
    return findings


def route(rec: FileRecord, bucket: Bucket, extract_dir: Path, logger: RunLogger) -> list[Finding]:
    match bucket:
        case Bucket.PDF:
            return d_pdf(rec, extract_dir, logger)
        case Bucket.RTF:
            return d_rtf(rec, extract_dir, logger)
        case Bucket.OOXML:
            return d_ooxml(rec, extract_dir, logger)
        case Bucket.OLE:
            return d_ole(rec, extract_dir, logger)
        case _:
            return []


def d_pdf(rec: FileRecord, extract_dir: Path, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    file_extract_dir = extract_dir / rec.sha256[:12]
    file_extract_dir.mkdir(parents=True, exist_ok=True)
    result = safe_subprocess(
        ["pdfimages", "-list", "--", rec.path],
        logger=logger,
        timeout=60,
    )
    if result.returncode == 0 and result.stdout.strip():
        lines = result.stdout.strip().splitlines()
        if len(lines) > 1:
            result2 = safe_subprocess(
                ["pdfimages", "-all", "--", rec.path, str(file_extract_dir / "img")],
                logger=logger,
                timeout=120,
            )
            if result2.returncode == 0:
                count = len(list(file_extract_dir.glob("img*")))
                if count:
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "embedded",
                            "embedded_object",
                            "pdf_image",
                            f"PDF contains {count} embedded images (extracted)",
                            f"{count} images in {file_extract_dir}",
                            "pdfimages",
                            Severity.LOW,
                            0.5,
                            extras={"count": count},
                        )
                    )
    return findings


def d_rtf(rec: FileRecord, extract_dir: Path, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    result = safe_subprocess(
        ["rtfobj", "-d", str(extract_dir / rec.sha256[:12]), "--", rec.path],
        logger=logger,
        timeout=60,
    )
    if result.returncode == 0 and ("OLE" in result.stdout or "object" in result.stdout.lower()):
        findings.append(
            Finding.from_file_record(
                rec,
                "embedded",
                "embedded_object",
                "rtf_ole",
                "RTF OLE objects extracted",
                result.stdout[:1000],
                "rtfobj",
                Severity.HIGH,
                0.7,
            )
        )
    return findings


def d_ooxml(rec: FileRecord, extract_dir: Path, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    file_extract_dir = extract_dir / rec.sha256[:12]
    file_extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        with zipfile.ZipFile(rec.path) as z:
            for name in z.namelist():
                if any(k in name.lower() for k in ("oleobject", "activex", "embeddings", "vbaproject", "embed")):
                    target = file_extract_dir / name.replace("/", "_")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    data = z.read(name)
                    target.write_bytes(data)
                    sha = hashlib.sha256(data).hexdigest()
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "embedded",
                            "embedded_object",
                            name.split("/")[-1],
                            f"OOXML embedded object extracted: {name}",
                            f"{name} (sha256={sha[:16]}, {len(data)} bytes)",
                            "unzip",
                            Severity.HIGH,
                            0.7,
                            extras={"extracted_path": str(target), "sha256": sha, "size": len(data)},
                        )
                    )
    except (zipfile.BadZipFile, OSError) as e:
        logger.log(f"Error extracting OOXML embedded objects from {rec.path}: {e}")
    return findings


def d_ole(rec: FileRecord, extract_dir: Path, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    result = safe_subprocess(
        ["oleobj", "-d", str(extract_dir / rec.sha256[:12]), "--", rec.path],
        logger=logger,
        timeout=60,
    )
    if result.returncode == 0 and "embedded" in result.stdout.lower():
        findings.append(
            Finding.from_file_record(
                rec,
                "embedded",
                "embedded_object",
                "ole_stream",
                "OLE embedded streams extracted",
                result.stdout[:1000],
                "oleobj",
                Severity.HIGH,
                0.7,
            )
        )
    return findings
