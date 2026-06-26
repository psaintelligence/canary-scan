"""Stage metadata: metadata extraction via exiftool."""

from __future__ import annotations

import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from canary_scan.lib.config import Severity
from canary_scan.lib.io import write_jsonl
from canary_scan.lib.models import FileRecord, Finding, make_info_finding
from canary_scan.lib.runners import RunLogger, safe_subprocess

PII_FIELDS = {
    "Author",
    "Creator",
    "LastModifiedBy",
    "Title",
    "Subject",
    "Description",
    "Comment",
    "Keywords",
    "Company",
    "Manager",
    "GPSPosition",
    "GPSLatitude",
    "GPSLongitude",
    "OwnerName",
    "CameraModelName",
    "SerialNumber",
    "InternalSerialNumber",
    "LensSerialNumber",
    "Artist",
    "Copyright",
}

SUSPICIOUS_FIELDS = {
    "DocumentID",
    "InstanceID",
    "OriginalDocumentID",
    "DerivedFromDocumentID",
    "VersionID",
    "Revision",
    "DocumentGuid",
    "DocId",
    "GUID",
    "Uuid",
}

URL_PATTERN_FIELDS = {"CreatorTool", "Producer", "Software", "Formatter"}


def _process_record(rec: FileRecord, logger: RunLogger) -> tuple[str, dict | None, list[Finding]]:
    try:
        findings: list[Finding] = []
        result = safe_subprocess(
            ["exiftool", "-a", "-G", "-j", "-n", "--", rec.path],
            logger=logger,
            timeout=60,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return rec.path, None, []
        try:
            data = json.loads(result.stdout)
            if isinstance(data, list) and data:
                fields = data[0]
            else:
                return rec.path, None, []
        except json.JSONDecodeError:
            return rec.path, None, []

        if rec.extension.lower() == ".pdf":
            import re
            import sys

            pdf_result = safe_subprocess(
                [sys.executable, "-m", "canary_scan.bundled.pdf_parser", "-s", "/FT", "--", rec.path],
                logger=logger,
                timeout=60,
            )
            if pdf_result.returncode == 0 and pdf_result.stdout.strip():
                stdout = pdf_result.stdout
                objects = re.split(r"(?m)^obj\s+", stdout)
                form_fields = []

                val_pattern = r"\s+(?:\((.*?)\)|<([^>]+)>|(\/[A-Za-z0-9_]+)|(\S+))"
                t_re = re.compile(r"/T" + val_pattern)
                tu_re = re.compile(r"/TU" + val_pattern)
                v_re = re.compile(r"/V" + val_pattern)
                ft_re = re.compile(r"/FT" + val_pattern)

                url_re = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
                ftp_re = re.compile(r"ftp://[^\s\"'<>]+", re.IGNORECASE)
                unc_re = re.compile(r"\\\\[\w.-]+\\[\w.-]+")

                for obj in objects:
                    if not obj.strip():
                        continue
                    lines = obj.splitlines()
                    header = lines[0].strip()

                    ft_match = ft_re.search(obj)
                    if not ft_match:
                        continue

                    # Safe extraction of the first non-None group
                    ft_val = next((x for x in ft_match.groups() if x is not None), None)
                    if not ft_val:
                        continue

                    t_val = None
                    t_match = t_re.search(obj)
                    if t_match:
                        t_val = next((x for x in t_match.groups() if x is not None), None)

                    tu_val = None
                    tu_match = tu_re.search(obj)
                    if tu_match:
                        tu_val = next((x for x in tu_match.groups() if x is not None), None)

                    v_val = None
                    v_match = v_re.search(obj)
                    if v_match:
                        v_val = next((x for x in v_match.groups() if x is not None), None)

                    field_info = {
                        "obj": header,
                        "ft": ft_val,
                    }
                    if t_val is not None:
                        field_info["t"] = t_val
                    if tu_val is not None:
                        field_info["tu"] = tu_val
                    if v_val is not None:
                        field_info["v"] = v_val

                    form_fields.append(field_info)

                    for name, txt in [("name", t_val), ("tooltip", tu_val), ("value", v_val)]:
                        if txt:
                            txt_str = str(txt)
                            for url in url_re.findall(txt_str):
                                findings.append(
                                    Finding.from_file_record(
                                        rec,
                                        stage="metadata",
                                        category="active_url",
                                        subcategory=f"pdf_form_{name}",
                                        finding=f"PDF Form field {name} contains remote URL: {url}",
                                        evidence=url,
                                        tool="pdf-parser",
                                        severity=Severity.CRITICAL,
                                        confidence=0.95,
                                    )
                                )
                            for ftp in ftp_re.findall(txt_str):
                                findings.append(
                                    Finding.from_file_record(
                                        rec,
                                        stage="metadata",
                                        category="active_url",
                                        subcategory=f"pdf_form_{name}_ftp",
                                        finding=f"PDF Form field {name} contains remote FTP: {ftp}",
                                        evidence=ftp,
                                        tool="pdf-parser",
                                        severity=Severity.CRITICAL,
                                        confidence=0.95,
                                    )
                                )
                            for unc in unc_re.findall(txt_str):
                                findings.append(
                                    Finding.from_file_record(
                                        rec,
                                        stage="metadata",
                                        category="active_url",
                                        subcategory=f"pdf_form_{name}_unc",
                                        finding=f"PDF Form field {name} contains remote UNC: {unc}",
                                        evidence=unc,
                                        tool="pdf-parser",
                                        severity=Severity.CRITICAL,
                                        confidence=0.95,
                                    )
                                )

                if form_fields:
                    fields["FormFields"] = form_fields
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            stage="metadata",
                            category="form_field",
                            subcategory="pdf_form",
                            finding=f"PDF contains {len(form_fields)} interactive form fields",
                            evidence=f"FormFields count: {len(form_fields)}",
                            tool="pdf-parser",
                            severity=Severity.MEDIUM,
                            confidence=0.8,
                        )
                    )

        for key, value in fields.items():
            if key in PII_FIELDS:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        stage="metadata",
                        category="metadata_pii",
                        subcategory=key.lower(),
                        finding=f"Metadata field {key} contains potential PII",
                        evidence=str(value)[:500],
                        tool="exiftool",
                        severity=Severity.MEDIUM,
                        confidence=0.6,
                    )
                )
            if key in SUSPICIOUS_FIELDS:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        stage="metadata",
                        category="metadata_unique",
                        subcategory=key.lower(),
                        finding=f"Metadata field {key} may contain a per-recipient unique identifier",
                        evidence=str(value)[:500],
                        tool="exiftool",
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                    )
                )
            val_str = str(value).lower()
            if "http://" in val_str or "https://" in val_str:
                if key in URL_PATTERN_FIELDS:
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            stage="metadata",
                            category="active_url",
                            subcategory=key.lower(),
                            finding=f"Metadata field {key} contains a URL",
                            evidence=str(value)[:500],
                            tool="exiftool",
                            severity=Severity.HIGH,
                            confidence=0.7,
                        )
                    )
        return rec.path, fields, findings
    except Exception as e:
        logger.log(f"Stage metadata: error on {rec.path}: {e}")
        return rec.path, None, [make_info_finding(rec, "metadata", f"metadata stage error: {e}")]


def run(
    records: list[FileRecord],
    outdir: Path,
    logger: RunLogger,
    workers: int = 4,
) -> tuple[dict[str, dict], list[Finding]]:
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    findings: list[Finding] = []
    metadata_map: dict[str, dict] = {}

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_process_record, rec, logger) for rec in records]
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Extracting metadata...", total=len(records))
            for future in futures:
                try:
                    path, fields, rec_findings = future.result()
                    if fields is not None:
                        metadata_map[path] = fields
                    findings.extend(rec_findings)
                except Exception as e:
                    logger.log(f"Stage metadata: future error: {e}")
                progress.advance(task)

    write_jsonl(findings, outdir / "canary-scan-metadata.json")
    logger.log(f"Stage metadata: extracted metadata for {len(metadata_map)} files, {len(findings)} findings")
    return metadata_map, findings
