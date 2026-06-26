"""Stage stego: steganography — steghide, opt-in stegseek."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from canary_scan.lib.config import Bucket, Severity
from canary_scan.lib.io import write_jsonl
from canary_scan.lib.models import FileRecord, Finding, make_info_finding
from canary_scan.lib.runners import RunLogger, safe_subprocess

STEGHIDE_EXTS = {".jpg", ".jpeg", ".bmp", ".wav", ".au"}


def _process_stego_record(rec: FileRecord, logger: RunLogger, crack_steg: str | None) -> list[Finding]:
    try:
        return scan_image(rec, logger, crack_steg)
    except Exception as e:
        logger.log(f"Stage stego: error on {rec.path}: {e}")
        return [make_info_finding(rec, "stego", f"stego stage error: {e}")]


def run(
    records: list[FileRecord],
    outdir: Path,
    logger: RunLogger,
    crack_steg: str | None = None,
    workers: int = 4,
) -> list[Finding]:
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    findings: list[Finding] = []
    image_records = [rec for rec in records if Bucket(rec.bucket) == Bucket.IMAGE]

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_process_stego_record, rec, logger, crack_steg) for rec in image_records]
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Auditing images / steganography...", total=len(image_records))
            for future in futures:
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logger.log(f"Stage stego: future error: {e}")
                progress.advance(task)

    write_jsonl(findings, outdir / "canary-scan-stego.json")
    logger.log(f"Stage stego: {len(findings)} steganography findings")
    return findings


def scan_image(rec: FileRecord, logger: RunLogger, crack_steg: str | None) -> list[Finding]:
    findings: list[Finding] = []
    ext = rec.extension.lower()

    if ext in STEGHIDE_EXTS:
        result = safe_subprocess(["steghide", "info", rec.path], logger=logger, timeout=30)
        if result.returncode == 0 or "embedded" in result.stderr.lower():
            findings.append(
                Finding.from_file_record(
                    rec,
                    "stego",
                    "steg_carrier",
                    "steghide",
                    "steghide reports this file is a steganography carrier",
                    result.stderr[:500] if result.stderr else result.stdout[:500],
                    "steghide",
                    Severity.HIGH,
                    0.7,
                )
            )
            if crack_steg:
                crack_result = safe_subprocess(
                    ["stegseek", rec.path, crack_steg],
                    logger=logger,
                    timeout=300,
                )
                if crack_result.returncode == 0 and crack_result.stdout:
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "stego",
                            "steg_payload",
                            "stegseek",
                            "stegseek cracked steghide payload (password found)",
                            crack_result.stdout[:1000],
                            "stegseek",
                            Severity.CRITICAL,
                            0.95,
                        )
                    )
    elif ext == ".png":
        result = safe_subprocess(["pngcheck", "--", rec.path], logger=logger, timeout=30)
        if result.returncode not in (0, 127):
            findings.append(
                Finding.from_file_record(
                    rec,
                    "stego",
                    "steg_carrier",
                    "pngcheck",
                    "pngcheck reports PNG file structure anomaly or trailing data",
                    result.stdout[:500] if result.stdout else result.stderr[:500],
                    "pngcheck",
                    Severity.HIGH,
                    0.7,
                )
            )

    # EXIF thumbnail mismatch check
    if ext in (".jpg", ".jpeg", ".png", ".tiff", ".tif"):
        try:
            thumb_result = safe_subprocess(
                ["exiftool", "-b", "-ThumbnailImage", "--", rec.path],
                logger=logger,
                timeout=30,
            )
            if thumb_result.returncode == 0 and thumb_result.stdout:
                thumb_bytes = thumb_result.stdout
                import io

                from PIL import Image

                with Image.open(rec.path) as img_main, Image.open(io.BytesIO(thumb_bytes)) as img_thumb:
                    ratio_main = img_main.width / img_main.height
                    ratio_thumb = img_thumb.width / img_thumb.height
                    ratio_mismatch = abs(ratio_main - ratio_thumb) > 0.15

                    def get_ahash(img) -> str:
                        small = img.resize((8, 8), Image.Resampling.LANCZOS).convert("L")
                        if hasattr(small, "get_flattened_data"):
                            pixels = list(small.get_flattened_data())
                        else:
                            pixels = list(small.getdata())
                        avg = sum(pixels) / 64
                        return "".join("1" if p > avg else "0" for p in pixels)

                    hash_main = get_ahash(img_main)
                    hash_thumb = get_ahash(img_thumb)
                    hamming_dist = sum(c1 != c2 for c1, c2 in zip(hash_main, hash_thumb, strict=True))

                    if ratio_mismatch or hamming_dist > 12:
                        evidence = f"Hamming: {hamming_dist}/64, Main aspect: {ratio_main:.2f}, Thumb aspect: {ratio_thumb:.2f}"
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "stego",
                                "steg_carrier",
                                "thumbnail_mismatch",
                                "EXIF thumbnail does not match the main image (potential stego/hidden content)",
                                evidence,
                                "exiftool+pillow",
                                Severity.HIGH,
                                0.8,
                            )
                        )
        except Exception as e:
            logger.log(f"Stage stego: error during thumbnail mismatch check on {rec.path}: {e}")

    # QR code detection
    if ext in (".jpg", ".jpeg", ".png", ".tiff", ".tif"):
        try:
            import re

            from PIL import Image
            from pyzbar import pyzbar

            URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
            FTP_RE = re.compile(r"ftp://[^\s\"'<>]+", re.IGNORECASE)
            UNC_RE = re.compile(r"\\\\[\w.-]+\\[\w.-]+")

            with Image.open(rec.path) as img:
                decoded = pyzbar.decode(img)
                for code in decoded:
                    data_str = code.data.decode("utf-8", errors="replace")
                    found_targets = []
                    found_targets.extend(URL_RE.findall(data_str))
                    found_targets.extend(FTP_RE.findall(data_str))
                    found_targets.extend(UNC_RE.findall(data_str))

                    for target in found_targets:
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "stego",
                                "active_url",
                                "qr_code_url",
                                f"Image QR code contains remote callback: {target}",
                                target,
                                "pyzbar",
                                Severity.HIGH,
                                0.9,
                            )
                        )
        except ImportError:
            pass
        except Exception as e:
            logger.log(f"Stage stego: error during QR code detection on {rec.path}: {e}")

    return findings
