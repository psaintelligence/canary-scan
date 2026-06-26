"""Stage uniqueness: uniqueness / near-duplicate fingerprinting — per-bucket clustering."""

from __future__ import annotations

import hashlib
import re
import zipfile
from collections import defaultdict
from pathlib import Path

from canary_scan.lib.config import Bucket, Severity
from canary_scan.lib.io import write_jsonl
from canary_scan.lib.models import FileRecord, Finding
from canary_scan.lib.runners import RunLogger, safe_subprocess


def _process_cluster(
    cluster_id: str,
    members: list[FileRecord],
    metadata: dict[str, dict],
    outdir: Path,
    logger: RunLogger,
    min_cluster_size: int,
) -> list[Finding]:
    findings: list[Finding] = []
    if len(members) < min_cluster_size:
        return findings
    try:
        diffs = _find_fingerprint_diffs(members, metadata, outdir, logger)
        for diff in diffs:
            for rec in members:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "uniqueness",
                        "unique_fingerprint",
                        diff.field,
                        f"Near-duplicate cluster differs by {diff.field}: {diff.description}",
                        diff.evidence,
                        "canary-scan",
                        Severity.MEDIUM,
                        0.8,
                        extras={"cluster_id": cluster_id, "cluster_size": len(members)},
                    )
                )
    except Exception as e:
        logger.log(f"Stage uniqueness: error on cluster {cluster_id}: {e}")
        from canary_scan.lib.models import make_info_finding

        for rec in members:
            findings.append(make_info_finding(rec, "uniqueness", f"uniqueness stage error: {e}"))
    return findings


def run(
    records: list[FileRecord],
    metadata: dict[str, dict],
    outdir: Path,
    logger: RunLogger,
    min_cluster_size: int = 2,
    fuzzy: bool = False,
    workers: int = 4,
) -> list[Finding]:
    from concurrent.futures import ProcessPoolExecutor

    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    findings: list[Finding] = []
    clusters = _build_clusters(records, metadata, fuzzy)
    logger.log(f"Stage uniqueness: {len(clusters)} clusters from {len(records)} files")

    active_clusters = {cid: mems for cid, mems in clusters.items() if len(mems) >= min_cluster_size}

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_process_cluster, cid, mems, metadata, outdir, logger, min_cluster_size)
            for cid, mems in active_clusters.items()
        ]
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Analyzing near-duplicate uniqueness...", total=len(futures))
            for future in futures:
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logger.log(f"Stage uniqueness: future error: {e}")
                progress.advance(task)

    write_jsonl(findings, outdir / "canary-scan-unique-clusters.json")
    logger.log(f"Stage uniqueness: {len(findings)} uniqueness findings")
    return findings


class Diff:
    def __init__(self, field: str, description: str, evidence: str) -> None:
        self.field = field
        self.description = description
        self.evidence = evidence


def _build_clusters(
    records: list[FileRecord],
    metadata: dict[str, dict],
    fuzzy: bool,
) -> dict[str, list[FileRecord]]:
    clusters: dict[str, list[FileRecord]] = defaultdict(list)
    for rec in records:
        meta = metadata.get(rec.path, {})
        key_parts = [rec.bucket]
        page_count = _extract_page_count(meta)
        if page_count:
            key_parts.append(f"pages={page_count}")
        producer = meta.get("PDF:Producer") or meta.get("Producer") or ""
        creator = meta.get("PDF:Creator") or meta.get("Creator") or ""
        if fuzzy:
            producer = re.sub(r"v?\d[\d.]+", "", producer).strip()
            creator = re.sub(r"v?\d[\d.]+", "", creator).strip()
        if producer:
            key_parts.append(f"prod={producer}")
        if creator:
            key_parts.append(f"creat={creator}")
        clusters["|".join(key_parts)].append(rec)
    return dict(clusters)


def _extract_page_count(meta: dict) -> str:
    for k in ("PDF:PageCount", "PageCount", "Pages"):
        if k in meta:
            return str(meta[k])
    return ""


def _find_fingerprint_diffs(
    members: list[FileRecord],
    metadata: dict[str, dict],
    outdir: Path,
    logger: RunLogger,
) -> list[Diff]:
    diffs: list[Diff] = []

    bucket = Bucket(members[0].bucket)
    match bucket:
        case Bucket.PDF:
            diffs = _diff_pdfs(members, outdir, logger, metadata)
        case Bucket.RTF:
            diffs = _diff_text(members)
        case Bucket.OOXML:
            diffs = _diff_ooxml(members)
        case Bucket.ODF:
            diffs = _diff_ooxml(members)
        case Bucket.OLE:
            diffs = _diff_text(members)
        case Bucket.IMAGE:
            diffs = _diff_images(members, metadata, logger)
        case _:
            diffs = _diff_metadata(members, metadata)

    return diffs


def _diff_pdfs(
    members: list[FileRecord], outdir: Path, logger: RunLogger, metadata: dict[str, dict] | None = None
) -> list[Diff]:
    diffs: list[Diff] = []
    if len(members) < 2:
        return diffs

    if metadata:
        pdf_fields = {}
        for rec in members:
            meta = metadata.get(rec.path, {})
            fields_list = meta.get("FormFields", [])
            fields_map = {}
            for f in fields_list:
                key = f.get("t") or f.get("obj")
                if key:
                    fields_map[key] = f
            pdf_fields[rec.path] = fields_map

        all_field_keys = set()
        for fields_map in pdf_fields.values():
            all_field_keys.update(fields_map.keys())

        mismatches = []
        for key in all_field_keys:
            values = {}
            tooltips = {}
            names = {}
            for rec in members:
                f = pdf_fields[rec.path].get(key, {})
                values[rec.path] = f.get("v")
                tooltips[rec.path] = f.get("tu")
                names[rec.path] = f.get("t")

            unique_values = set(values.values())
            unique_tooltips = set(tooltips.values())
            unique_names = set(names.values())

            if len(unique_values) > 1:
                evidence_items = [f"{Path(p).name}: {v!r}" for p, v in values.items()]
                mismatches.append(f"field '{key}' value differs ({', '.join(evidence_items)})")
            if len(unique_tooltips) > 1:
                evidence_items = [f"{Path(p).name}: {t!r}" for p, t in tooltips.items()]
                mismatches.append(f"field '{key}' tooltip differs ({', '.join(evidence_items)})")
            if len(unique_names) > 1:
                evidence_items = [f"{Path(p).name}: {n!r}" for p, n in names.items()]
                mismatches.append(f"field '{key}' name differs ({', '.join(evidence_items)})")

        if mismatches:
            diffs.append(
                Diff(
                    "pdf_form_field",
                    "interactive form field value/name differs among near-duplicates",
                    "; ".join(mismatches),
                )
            )
    normalized: list[str] = []
    tmp_dir = outdir / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    for rec in members:
        tmp = tmp_dir / f"canary-scan-qdf-{rec.sha256[:12]}.pdf"
        try:
            result = safe_subprocess(
                ["qpdf", "--qdf", rec.path, str(tmp)],
                logger=logger,
                timeout=60,
            )
            if result.returncode == 0 and tmp.exists():
                normalized.append(tmp.read_text(encoding="utf-8", errors="replace"))
            else:
                normalized.append("")
        finally:
            if tmp.exists():
                import contextlib

                with contextlib.suppress(OSError):
                    tmp.unlink()

    normalized_hashes = set(hashlib.sha256(n.encode()).hexdigest() for n in normalized)
    if len(normalized_hashes) > 1:
        diffs.append(
            Diff(
                "pdf_normalized_bytes",
                "normalized PDF bodies differ (potential per-recipient watermark)",
                "qpdf --qdf diff",
            )
        )
    else:
        png_hashes = []
        png_paths = []
        try:
            for rec in members:
                png_path = tmp_dir / f"canary-scan-page-{rec.sha256[:12]}.png"
                png_paths.append(png_path)
                result = safe_subprocess(
                    ["mutool", "draw", "-o", str(png_path), "-r", "150", rec.path, "1"],
                    logger=logger,
                    timeout=30,
                )
                if result.returncode == 0 and png_path.exists():
                    png_data = png_path.read_bytes()
                    png_hashes.append(hashlib.sha256(png_data).hexdigest())
                else:
                    png_hashes.append("")
            if len(set(png_hashes)) > 1:
                diffs.append(
                    Diff(
                        "pdf_pixel_diff",
                        "rendered PDF pages differ visually (potential yellow dots or per-recipient watermark)",
                        "mutool draw page diff",
                    )
                )
        finally:
            for p in png_paths:
                if p.exists():
                    import contextlib

                    with contextlib.suppress(OSError):
                        p.unlink()
    return diffs


def _diff_text(members: list[FileRecord]) -> list[Diff]:
    diffs: list[Diff] = []
    if len(members) < 2:
        return diffs
    contents = []
    for rec in members:
        try:
            with open(rec.path, encoding="utf-8", errors="replace") as f:
                contents.append(f.read())
        except OSError:
            contents.append("")
    hashes = {hashlib.sha256(c.encode()).hexdigest() for c in contents}
    if len(hashes) > 1:

        def canonicalize(text: str) -> str:
            text = text.lstrip("\ufeff")
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            lines = [line.rstrip() for line in text.split("\n")]
            return "\n".join(lines).strip()

        canon_hashes = {hashlib.sha256(canonicalize(c).encode()).hexdigest() for c in contents}
        if len(canon_hashes) == 1:
            diffs.append(
                Diff(
                    "canonicalization_diff",
                    "files differ only by canonicalization (whitespace/newlines) (potential fingerprinting)",
                    "whitespace/newline differences",
                )
            )
        else:
            diffs.append(Diff("raw_text_bytes", "file bodies differ among near-duplicates", "raw text hash differs"))
    return diffs


def _diff_ooxml(members: list[FileRecord]) -> list[Diff]:
    diffs: list[Diff] = []
    if len(members) < 2:
        return diffs
    core_xmls: list[str] = []
    for rec in members:
        try:
            with zipfile.ZipFile(rec.path) as z:
                core = (
                    z.read("docProps/core.xml").decode("utf-8", errors="replace")
                    if "docProps/core.xml" in z.namelist()
                    else ""
                )
        except (zipfile.BadZipFile, OSError):
            core = ""
        guid = re.search(r"<(?:cp:|)guid[^>]*>([^<]+)<", core, re.IGNORECASE)
        revision = re.search(r"<(?:cp:|)revision[^>]*>([^<]+)<", core, re.IGNORECASE)
        if guid:
            core_xmls.append(f"guid={guid.group(1)}")
        if revision:
            core_xmls.append(f"rev={revision.group(1)}")
    if len(set(core_xmls)) > 1:
        diffs.append(
            Diff(
                "core_xml_guid_revision",
                "OOXML core.xml GUID or revision differs among near-duplicates",
                " | ".join(core_xmls),
            )
        )
    return diffs


def _diff_images(members: list[FileRecord], metadata: dict[str, dict], logger: RunLogger) -> list[Diff]:
    diffs: list[Diff] = []
    if len(members) < 2:
        return diffs
    sizes = set()
    for rec in members:
        meta = metadata.get(rec.path, {})
        w = meta.get("ImageWidth") or meta.get("ExifImageWidth") or ""
        h = meta.get("ImageHeight") or meta.get("ExifImageHeight") or ""
        sizes.add(f"{w}x{h}")
    if len(sizes) > 1:
        diffs.append(Diff("image_dimensions", "image dimensions differ among near-duplicates", str(sizes)))
    result = safe_subprocess(
        ["compare", "-metric", "AE", members[0].path, members[1].path, "/dev/null"],
        logger=logger,
        timeout=30,
    )
    if result.returncode in (0, 1) and result.stderr.strip():
        try:
            ae = int(result.stderr.strip())
            if 0 < ae < 1000:
                diffs.append(Diff("pixel_diff", f"images differ by {ae} pixels (subtle watermark?)", str(ae)))
        except ValueError:
            pass
    return diffs


def _diff_metadata(members: list[FileRecord], metadata: dict[str, dict]) -> list[Diff]:
    diffs: list[Diff] = []
    if len(members) < 2:
        return diffs
    keys_to_check = ("DocumentID", "InstanceID", "OriginalDocumentID", "GUID", "DocId")
    for key in keys_to_check:
        vals = set()
        for rec in members:
            meta = metadata.get(rec.path, {})
            val = str(meta.get(key, ""))
            if val:
                vals.add(val)
        if len(vals) > 1:
            diffs.append(Diff(key.lower(), f"metadata field {key} differs among near-duplicates", str(vals)))
    return diffs
