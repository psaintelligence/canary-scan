"""Stage remote-refs: remote references — per-bucket routing for active phone-home canaries."""

from __future__ import annotations

import email
import json
import os
import re
import sys
import tarfile
import zipfile
import zlib
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from canary_scan.lib.config import Bucket, Severity
from canary_scan.lib.io import write_jsonl
from canary_scan.lib.models import FileRecord, Finding, make_info_finding
from canary_scan.lib.runners import RunLogger, safe_subprocess

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
FTP_RE = re.compile(r"ftp://[^\s\"'<>]+", re.IGNORECASE)
UNC_RE = re.compile(r"\\\\[\w.-]+\\[\w.-]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _clean_url(url: str) -> tuple[str, bool]:
    cleaned = url.strip().strip(")").strip(">").strip("<").strip('"').strip("'")
    thinkst_pattern = "/QXUGUTAENT"
    is_thinkst = False
    if thinkst_pattern in cleaned:
        is_thinkst = True
        idx = cleaned.find(thinkst_pattern)
        cleaned = cleaned[:idx].strip()
        if not cleaned.endswith("/"):
            cleaned += "/"
    return cleaned, is_thinkst


def _scan_raw_text(
    rec: FileRecord,
    text: str,
    tool: str,
    subcategory: str,
    severity: Severity,
    confidence: float,
    category: str = "active_url",
) -> list[Finding]:
    findings = []
    # 1. HTTP/S URLs
    for url in URL_RE.findall(text):
        cleaned, is_thinkst = _clean_url(url)
        if not cleaned:
            continue
        if is_thinkst:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "active_url",
                    "thinkst_canarytoken",
                    f"Thinkst Canarytoken detected: {cleaned}",
                    cleaned,
                    tool,
                    Severity.CRITICAL,
                    1.0,
                )
            )
        else:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    category,
                    subcategory,
                    f"{rec.bucket.upper()} references external URL: {cleaned}",
                    cleaned,
                    tool,
                    severity,
                    confidence,
                )
            )
    # 2. FTP URLs
    for ftp in FTP_RE.findall(text):
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "active_url",
                f"{subcategory}_ftp",
                f"{rec.bucket.upper()} references external FTP path: {ftp}",
                ftp,
                tool,
                severity,
                confidence,
            )
        )
    # 3. UNC Paths
    for unc in UNC_RE.findall(text):
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "active_url",
                "unc_path",
                f"{rec.bucket.upper()} references external UNC path: {unc}",
                unc,
                tool,
                Severity.CRITICAL,
                0.9,
            )
        )
    return findings


def _process_remote_refs_record(
    rec: FileRecord,
    logger: RunLogger,
    max_archive_depth: int,
    enable_specialized: bool,
) -> list[Finding]:
    bucket = Bucket(rec.bucket)
    try:
        return route(rec, bucket, logger, max_archive_depth, enable_specialized, depth=0)
    except Exception as e:
        logger.log(f"Stage remote-refs: error on {rec.path}: {e}")
        return [make_info_finding(rec, "remote-refs", f"remote-refs stage error: {e}")]


def run(
    records: list[FileRecord],
    outdir: Path,
    logger: RunLogger,
    workers: int = 4,
    max_archive_depth: int = 3,
    enable_specialized: bool = False,
) -> list[Finding]:
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeRemainingColumn

    findings: list[Finding] = []

    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_process_remote_refs_record, rec, logger, max_archive_depth, enable_specialized)
            for rec in records
        ]
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task("Scanning remote references...", total=len(records))
            for future in futures:
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logger.log(f"Stage remote-refs: future error: {e}")
                progress.advance(task)

    write_jsonl(findings, outdir / "canary-scan-remote-refs.json")
    logger.log(f"Stage remote-refs: {len(findings)} remote-reference findings")
    return findings


def route(
    rec: FileRecord,
    bucket: Bucket,
    logger: RunLogger,
    max_depth: int,
    enable_specialized: bool,
    depth: int,
) -> list[Finding]:
    if depth > max_depth:
        return [make_info_finding(rec, "remote-refs", f"max archive depth {max_depth} exceeded, not recursing")]
    if rec.extension == ".lnk":
        return c_lnk(rec, logger)
    match bucket:
        case Bucket.PDF:
            return c_pdf(rec, logger)
        case Bucket.RTF:
            return c_rtf(rec, logger)
        case Bucket.OOXML:
            return c_ooxml(rec, logger)
        case Bucket.ODF:
            return c_odf(rec, logger)
        case Bucket.OLE:
            return c_ole(rec, logger)
        case Bucket.HTML:
            return c_html(rec, logger)
        case Bucket.EMAIL:
            return c_email(rec, logger)
        case Bucket.IMAGE:
            return c_image(rec, logger)
        case Bucket.CSV:
            return c_csv(rec)
        case Bucket.XML:
            return c_xml(rec)
        case Bucket.ARCHIVE:
            return c_archive(rec, logger, max_depth, enable_specialized, depth)
        case _:
            return []


def c_pdf(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []

    # Incremental update detection
    raw_bytes = _read_bytes(rec.path)
    if raw_bytes:
        eof_count = raw_bytes.count(b"%%EOF")
        if eof_count > 1:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "incremental_update",
                    "pdf_incremental",
                    f"PDF contains {eof_count} incremental updates (%%EOF markers)",
                    f"%%EOF count: {eof_count}",
                    "canary-scan",
                    Severity.MEDIUM,
                    0.8,
                )
            )

    # In-memory stream extraction & raw bytes URL scan
    PDF_STREAM_RE = re.compile(rb"stream[\r\n\s]+(.*?)[\r\n\s]+endstream", re.DOTALL)
    if raw_bytes:
        # Find streams and decompress
        for m in PDF_STREAM_RE.finditer(raw_bytes):
            stream_data = m.group(1)
            for wbits in (None, -15):
                try:
                    if wbits is None:
                        decompressed = zlib.decompress(stream_data)
                    else:
                        decompressed = zlib.decompress(stream_data, wbits)
                    decomp_text = decompressed.decode("utf-8", errors="ignore")
                    findings.extend(
                        _scan_raw_text(
                            rec,
                            decomp_text,
                            "pdf-stream-decompressor",
                            "pdf_stream_url",
                            Severity.CRITICAL,
                            0.9,
                        )
                    )
                except zlib.error:
                    pass
        # Raw bytes scan (plain text URLs/UNCs)
        try:
            raw_text = raw_bytes.decode("utf-8", errors="ignore")
            findings.extend(
                _scan_raw_text(
                    rec,
                    raw_text,
                    "pdf-raw-scanner",
                    "pdf_raw_url",
                    Severity.CRITICAL,
                    0.9,
                )
            )
        except Exception:
            pass

    result = safe_subprocess(
        [sys.executable, "-m", "canary_scan.bundled.pdfid", "--", rec.path],
        logger=logger,
        timeout=60,
    )
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            line = line.strip()
            if "/Encrypt" in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        count = int(parts[1])
                        if count > 0:
                            findings.append(
                                Finding.from_file_record(
                                    rec,
                                    "remote-refs",
                                    "encrypted_file",
                                    "pdf_encrypt",
                                    "PDF is encrypted / password-protected (/Encrypt dictionary present)",
                                    line,
                                    "pdfid",
                                    Severity.MEDIUM,
                                    0.9,
                                )
                            )
                    except ValueError:
                        pass
            elif any(
                k in line
                for k in (
                    "/JS",
                    "/JavaScript",
                    "/OpenAction",
                    "/AA",
                    "/URI",
                    "/Launch",
                    "/GoToR",
                    "/EmbeddedFile",
                    "/XFA",
                    "/RichMedia",
                )
            ):
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "javascript"
                        if "/JS" in line or "/JavaScript" in line
                        else "open_action"
                        if "/OpenAction" in line or "/AA" in line
                        else "active_url",
                        line.split()[0] if line else "",
                        f"PDF contains suspicious element: {line}",
                        line,
                        "pdfid",
                        Severity.HIGH if "/JS" in line else Severity.CRITICAL,
                        0.8,
                    )
                )

    for search_term in ("/URI", "/Launch", "/GoToR", "/AcroForm", "/OCProperties", "/OCG", "/Sig"):
        result = safe_subprocess(
            [sys.executable, "-m", "canary_scan.bundled.pdf_parser", "-s", search_term, "--", rec.path],
            logger=logger,
            timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            # If we found any URLs/FTP/UNC inside this object, extract them
            findings.extend(_scan_raw_text(rec, result.stdout, "pdf-parser", "uri_action", Severity.CRITICAL, 0.9))

            if search_term == "/AcroForm" and "/AcroForm" in result.stdout:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "form_field",
                        "pdf_form",
                        "PDF contains form fields (/AcroForm interactive form catalog)",
                        "/AcroForm found in PDF structure",
                        "pdf-parser",
                        Severity.MEDIUM,
                        0.7,
                    )
                )
            elif search_term in ("/OCProperties", "/OCG") and search_term in result.stdout:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "watermark",
                        "pdf_ocg",
                        f"PDF contains Optional Content Groups / Watermark Layers ({search_term})",
                        f"{search_term} found in PDF structure",
                        "pdf-parser",
                        Severity.HIGH,
                        0.7,
                    )
                )
            elif search_term == "/Sig" and "/Sig" in result.stdout:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "suspicious_metadata_field",
                        "pdf_signature",
                        "PDF contains digital signature object (/Sig)",
                        "/Sig found in PDF structure",
                        "pdf-parser",
                        Severity.INFO,
                        0.6,
                    )
                )

    return findings


def c_rtf(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    result = safe_subprocess(["rtfobj", "--", rec.path], logger=logger, timeout=60)
    if result.returncode == 0:
        if "objdata" in result.stdout.lower() or "OLE" in result.stdout:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "embedded_object",
                    "objdata",
                    "RTF contains OLE object (objdata)",
                    result.stdout[:1000],
                    "rtfobj",
                    Severity.HIGH,
                    0.7,
                )
            )
    raw = _read_text(rec.path)
    if raw:
        findings.extend(_scan_raw_text(rec, raw, "rg", "hyperlink", Severity.CRITICAL, 0.8))
        if "\\objhtml" in raw or "\\objupdate" in raw:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "embedded_object",
                    "objhtml",
                    "RTF contains auto-update OLE object",
                    "\\objhtml/\\objupdate",
                    "rg",
                    Severity.CRITICAL,
                    0.9,
                )
            )
    return findings


def c_ooxml(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    dde_re = re.compile(r"\b(DDE|DDEAUTO)\b", re.IGNORECASE)
    MAX_ZIP_MEMBER_SIZE = 20 * 1024 * 1024
    try:
        with zipfile.ZipFile(rec.path) as z:
            for info in z.infolist():
                if info.flag_bits & 0x1:
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "encrypted_file",
                            "zip_encrypt",
                            "OOXML/ZIP archive member is encrypted / password-protected",
                            info.filename,
                            "zipfile",
                            Severity.MEDIUM,
                            0.9,
                        )
                    )
                    return findings

            names = z.namelist()
            for name in names:
                try:
                    info = z.getinfo(name)
                except KeyError:
                    continue
                if info.is_dir() or info.file_size > MAX_ZIP_MEMBER_SIZE:
                    continue

                if "printersettings" in name.lower():
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "suspicious_metadata_field",
                            "ooxml_printer_settings",
                            f"OOXML contains embedded printer settings: {name}",
                            name,
                            "unzip",
                            Severity.INFO,
                            0.6,
                        )
                    )

                if "oleobject" in name.lower() or "activex" in name.lower() or "embeddings" in name.lower():
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "embedded_object",
                            name.split("/")[-1],
                            f"OOXML contains embedded object: {name}",
                            name,
                            "unzip",
                            Severity.HIGH,
                            0.7,
                        )
                    )

                if "vbaproject" in name.lower():
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "javascript",
                            "vba",
                            f"OOXML contains VBA project: {name}",
                            name,
                            "unzip",
                            Severity.HIGH,
                            0.8,
                        )
                    )

                try:
                    raw_data = z.read(name)
                except Exception:
                    continue

                data = raw_data.decode("utf-8", errors="replace")

                if name.endswith("core.xml"):
                    for creator in re.findall(r"<dc:creator>([^<]+)</dc:creator>", data):
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "remote-refs",
                                "metadata_pii",
                                "ooxml_creator",
                                f"OOXML metadata contains creator name: {creator}",
                                creator,
                                "unzip+regex",
                                Severity.LOW,
                                0.8,
                            )
                        )
                    for modifier in re.findall(r"<cp:lastModifiedBy>([^<]+)</cp:lastModifiedBy>", data):
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "remote-refs",
                                "metadata_pii",
                                "ooxml_last_modifier",
                                f"OOXML metadata contains last modifier: {modifier}",
                                modifier,
                                "unzip+regex",
                                Severity.LOW,
                                0.8,
                            )
                        )
                    for printed in re.findall(r"<cp:lastPrinted>([^<]+)</cp:lastPrinted>", data):
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "remote-refs",
                                "metadata_pii",
                                "ooxml_last_printed",
                                f"OOXML metadata contains last printed timestamp: {printed}",
                                printed,
                                "unzip+regex",
                                Severity.LOW,
                                0.8,
                            )
                        )

                if dde_re.search(data):
                    match = dde_re.search(data)
                    context = data[max(0, match.start() - 100) : min(len(data), match.end() + 100)]
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "javascript",
                            "dde_link",
                            f"OOXML part {name} contains DDE / DDEAUTO link",
                            context.strip(),
                            "unzip+rg",
                            Severity.CRITICAL,
                            0.9,
                        )
                    )

                if name.endswith(".rels") and 'TargetMode="External"' in data:
                    findings.extend(_scan_raw_text(rec, data, "unzip+rg", "external_rel", Severity.CRITICAL, 0.9))
                elif any(p in name.lower() for p in ("header", "footer", "document.xml", "[content_types].xml")):
                    findings.extend(_scan_raw_text(rec, data, "unzip+rg", name.split("/")[-1], Severity.HIGH, 0.8))
                elif "customxml" in name.lower():
                    findings.extend(_scan_raw_text(rec, data, "unzip+rg", "customxml", Severity.MEDIUM, 0.6))
                else:
                    findings.extend(
                        _scan_raw_text(rec, data, "unzip+rg", f"zip_member_{name.split('/')[-1]}", Severity.HIGH, 0.7)
                    )

    except Exception as e:
        err_msg = str(e).lower()
        if "encrypted" in err_msg or "password" in err_msg:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "encrypted_file",
                    "zip_encrypt_error",
                    f"OOXML/ZIP parsing failed due to encryption: {e}",
                    str(e),
                    "zipfile",
                    Severity.MEDIUM,
                    0.9,
                )
            )
            return findings
        logger.log(f"Stage remote-refs: ZIP error on {rec.path}: {e}")
    return findings


def c_odf(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with zipfile.ZipFile(rec.path) as z:
            for name in z.namelist():
                if name.endswith(".xml"):
                    data = z.read(name).decode("utf-8", errors="replace")
                    if name in ("content.xml", "styles.xml", "meta.xml"):
                        findings.extend(
                            _scan_raw_text(
                                rec,
                                data,
                                "unzip+rg",
                                name,
                                Severity.MEDIUM if name == "meta.xml" else Severity.CRITICAL,
                                0.8,
                            )
                        )
    except (zipfile.BadZipFile, OSError) as e:
        logger.log(f"Error parsing ODF file {rec.path}: {e}")
    return findings


def c_ole(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    result = safe_subprocess(["olevba", "--", rec.path], logger=logger, timeout=60)
    if result.returncode == 0 and "VBA" in result.stdout:
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "javascript",
                "vba",
                "OLE file contains VBA macros",
                result.stdout[:1000],
                "olevba",
                Severity.HIGH,
                0.7,
            )
        )
        findings.extend(_scan_raw_text(rec, result.stdout, "olevba", "vba_url", Severity.CRITICAL, 0.9))

        # Check for system environment gathering keywords/APIs
        env_pattern = re.compile(r"\b(Environ|ComputerName|UserName|RegRead|WScript\.Network)\b", re.IGNORECASE)
        matches = env_pattern.findall(result.stdout)
        if matches:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "javascript",
                    "macro_fingerprint",
                    f"VBA macro gathers environment information: {', '.join(set(matches))}",
                    result.stdout[:2000],
                    "olevba",
                    Severity.HIGH,
                    0.8,
                )
            )
    result = safe_subprocess(["oleobj", "--", rec.path], logger=logger, timeout=60)
    if result.returncode == 0 and "embedded" in result.stdout.lower():
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "embedded_object",
                "ole_embedded",
                "OLE file contains embedded objects",
                result.stdout[:1000],
                "oleobj",
                Severity.HIGH,
                0.7,
            )
        )
    raw = _read_bytes(rec.path)
    if raw:
        findings.extend(
            _scan_raw_text(
                rec,
                raw.decode("utf-8", errors="replace"),
                "strings",
                "hyperlink",
                Severity.CRITICAL,
                0.8,
            )
        )

    # OLE stream scanning via olefile
    try:
        import olefile

        if olefile.isOleFile(rec.path):
            with olefile.OleFileIO(rec.path) as ole:
                for stream_name in ole.listdir():
                    try:
                        data = ole.openstream(stream_name).read()
                        text_u8 = data.decode("utf-8", errors="replace")
                        findings.extend(
                            _scan_raw_text(
                                rec,
                                text_u8,
                                "olefile",
                                f"ole_stream/{'/'.join(stream_name)}",
                                Severity.CRITICAL,
                                0.8,
                            )
                        )
                        text_u16 = data.decode("utf-16", errors="replace")
                        findings.extend(
                            _scan_raw_text(
                                rec,
                                text_u16,
                                "olefile",
                                f"ole_stream/{'/'.join(stream_name)}",
                                Severity.CRITICAL,
                                0.8,
                            )
                        )
                    except Exception:
                        pass
    except Exception as e:
        logger.log(f"OLE stream parsing error on {rec.path}: {e}")

    if rec.path.endswith(".msg"):
        findings.extend(c_msg(rec, logger))
    return findings


def c_msg(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    try:
        import extract_msg

        msg = extract_msg.Message(rec.path)
        if msg.htmlBody:
            body = msg.htmlBody
            html = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
            findings.extend(
                _scan_raw_text(
                    rec,
                    html,
                    "extract_msg",
                    "msg_html_url",
                    Severity.CRITICAL,
                    0.9,
                    category="tracking_pixel",
                )
            )

        if hasattr(msg, "headerDict") and msg.headerDict:
            for header, values in msg.headerDict.items():
                header_lower = header.lower()
                if header_lower.startswith("x-") or header_lower in ("received", "user-agent", "message-id"):
                    val_list = values if isinstance(values, list) else [values]
                    for val in val_list:
                        findings.extend(
                            _scan_raw_text(
                                rec,
                                str(val),
                                "extract_msg",
                                f"email_header/{header_lower.replace('-', '_')}",
                                Severity.INFO,
                                0.5,
                                category="suspicious_metadata_field",
                            )
                        )
    except Exception as e:
        logger.log(f"Error parsing MSG file {rec.path}: {e}")
    return findings


def c_html(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []

    if rec.path.lower().endswith((".mht", ".mhtml")):
        try:
            with open(rec.path, "rb") as f:
                msg = email.message_from_binary_file(f)
            for header, value in msg.items():
                if header.lower() == "content-location":
                    findings.extend(_scan_raw_text(rec, value, "mhtml", "header_content_location", Severity.HIGH, 0.8))
            for part in msg.walk():
                for p_hdr, p_val in part.items():
                    if p_hdr.lower() == "content-location":
                        findings.extend(
                            _scan_raw_text(rec, p_val, "mhtml", "part_content_location", Severity.HIGH, 0.8)
                        )
                body = part.get_payload(decode=True)
                if body:
                    body_text = body.decode("utf-8", errors="replace")
                    findings.extend(_scan_raw_text(rec, body_text, "mhtml", "part_body", Severity.HIGH, 0.8))
        except Exception as e:
            logger.log(f"MHTML parsing error on {rec.path}: {e}")
        return findings

    raw = _read_text(rec.path)
    if not raw:
        return findings
    lowered = raw.lower()
    for url in URL_RE.findall(raw):
        tag = _tag_for_url(raw, url)
        if tag in ("img",):
            if _is_tracking_pixel(raw, url):
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "tracking_pixel",
                        "img_beacon",
                        f"HTML tracking pixel image: {url}",
                        url,
                        "rg",
                        Severity.CRITICAL,
                        0.9,
                    )
                )
            else:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "active_url",
                        "img",
                        f"HTML external image: {url}",
                        url,
                        "rg",
                        Severity.HIGH,
                        0.7,
                    )
                )
        elif tag in ("script",):
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "javascript",
                    "script_src",
                    f"HTML external script: {url}",
                    url,
                    "rg",
                    Severity.CRITICAL,
                    0.9,
                )
            )
        elif tag in ("iframe",):
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "active_url",
                    "iframe",
                    f"HTML iframe: {url}",
                    url,
                    "rg",
                    Severity.CRITICAL,
                    0.9,
                )
            )
        else:
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "active_url",
                    tag or "link",
                    f"HTML references URL in <{tag}>: {url}",
                    url,
                    "rg",
                    Severity.MEDIUM,
                    0.6,
                )
            )
    for ftp in FTP_RE.findall(raw):
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "active_url",
                "ftp",
                f"HTML references FTP: {ftp}",
                ftp,
                "rg",
                Severity.HIGH,
                0.7,
            )
        )
    for unc in UNC_RE.findall(raw):
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "active_url",
                "unc_path",
                f"HTML references UNC path: {unc}",
                unc,
                "rg",
                Severity.CRITICAL,
                0.9,
            )
        )
    if "ping=" in lowered:
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "tracking_pixel",
                "ping",
                "HTML contains ping= attribute (tracker)",
                "ping=",
                "rg",
                Severity.HIGH,
                0.7,
            )
        )
    return findings


def c_email(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    try:
        with open(rec.path, "rb") as f:
            msg = email.message_from_binary_file(f)
    except OSError:
        return findings

    disposition = msg.get("Disposition-Notification-To", "")
    for header, value in msg.items():
        header_lower = header.lower()
        if header_lower.startswith("x-") or header_lower in ("received", "user-agent", "message-id"):
            findings.extend(
                _scan_raw_text(
                    rec,
                    value,
                    "email",
                    f"email_header/{header_lower.replace('-', '_')}",
                    Severity.INFO,
                    0.5,
                    category="suspicious_metadata_field",
                )
            )
    if disposition:
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "read_receipt",
                "disposition_notification",
                f"Email requests read receipt to: {disposition}",
                disposition,
                "email",
                Severity.MEDIUM,
                0.7,
            )
        )
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            body = part.get_payload(decode=True)
            if body:
                html = body.decode("utf-8", errors="replace")
                for url in URL_RE.findall(html):
                    if _is_tracking_pixel(html, url):
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "remote-refs",
                                "tracking_pixel",
                                "eml_beacon",
                                f"Email HTML tracking pixel: {url}",
                                url,
                                "email",
                                Severity.CRITICAL,
                                0.9,
                            )
                        )
                    else:
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "remote-refs",
                                "active_url",
                                "eml_img",
                                f"Email HTML external resource: {url}",
                                url,
                                "email",
                                Severity.HIGH,
                                0.7,
                            )
                        )
                for ftp in FTP_RE.findall(html):
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "active_url",
                            "eml_ftp",
                            f"Email HTML external FTP path: {ftp}",
                            ftp,
                            "email",
                            Severity.HIGH,
                            0.7,
                        )
                    )
                for unc in UNC_RE.findall(html):
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "active_url",
                            "unc_path",
                            f"Email HTML external UNC path: {unc}",
                            unc,
                            "email",
                            Severity.CRITICAL,
                            0.9,
                        )
                    )
    return findings


def c_image(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    if rec.extension == ".svg":
        try:
            from defusedxml import ElementTree as DefusedET

            tree = DefusedET.parse(rec.path)
            root = tree.getroot()
            for elem in root.iter():
                for attr_name, attr_val in elem.attrib.items():
                    if attr_name.endswith("href") or attr_name == "href":
                        if URL_RE.match(attr_val) or FTP_RE.match(attr_val) or UNC_RE.match(attr_val):
                            findings.append(
                                Finding.from_file_record(
                                    rec,
                                    "remote-refs",
                                    "active_url",
                                    "svg_href",
                                    f"SVG external href: {attr_val}",
                                    attr_val,
                                    "xml",
                                    Severity.CRITICAL
                                    if "script" in elem.tag.lower() or UNC_RE.match(attr_val)
                                    else Severity.HIGH,
                                    0.8,
                                )
                            )
                if "script" in elem.tag.lower():
                    findings.append(
                        Finding.from_file_record(
                            rec,
                            "remote-refs",
                            "javascript",
                            "svg_script",
                            "SVG contains <script> element",
                            elem.tag,
                            "xml",
                            Severity.HIGH,
                            0.8,
                        )
                    )
        except Exception:
            pass
    else:
        result = safe_subprocess(["exiftool", "-ee", "-b", "-j", "--", rec.path], logger=logger, timeout=60)
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                if isinstance(data, list) and data:
                    for key, val in data[0].items():
                        val_str = str(val)
                        findings.extend(_scan_raw_text(rec, val_str, "exiftool", key.lower(), Severity.MEDIUM, 0.6))
            except json.JSONDecodeError:
                pass
    return findings


def c_csv(rec: FileRecord) -> list[Finding]:
    findings: list[Finding] = []
    try:
        import csv

        with open(rec.path, encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                for cell in row:
                    cell = cell.strip()
                    if cell and cell[0] in ("=", "+", "-", "@"):
                        if (
                            re.match(r"=(HYPERLINK|WEBSERVICE|IMPORTDATA|IMPORTXML|IMAGE)\b", cell, re.IGNORECASE)
                            or "cmd|" in cell
                        ):
                            findings.append(
                                Finding.from_file_record(
                                    rec,
                                    "remote-refs",
                                    "formula_injection",
                                    "csv_formula",
                                    f"CSV cell contains formula injection: {cell[:100]}",
                                    cell[:200],
                                    "canary-scan",
                                    Severity.MEDIUM,
                                    0.8,
                                )
                            )
                            findings.extend(
                                _scan_raw_text(rec, cell, "canary-scan", "csv_formula_url", Severity.CRITICAL, 0.9)
                            )
    except (OSError, csv.Error):
        pass
    return findings


def c_xml(rec: FileRecord) -> list[Finding]:
    findings: list[Finding] = []
    has_error = False
    try:
        from defusedxml import ElementTree as DefusedET

        DefusedET.parse(rec.path)
    except Exception:
        has_error = True

    raw = _read_text(rec.path)
    if not raw:
        return findings

    for m in re.finditer(r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"']([^\"']+)[\"']", raw, re.IGNORECASE):
        findings.append(
            Finding.from_file_record(
                rec,
                "remote-refs",
                "external_entity",
                "xxe",
                f"XML external entity (XXE): {m.group(1)}",
                m.group(1),
                "regex",
                Severity.CRITICAL,
                0.8,
            )
        )

    if not has_error:
        for m in re.finditer(r"document\s*\(\s*[\"']([^\"']+)[\"']", raw, re.IGNORECASE):
            findings.append(
                Finding.from_file_record(
                    rec,
                    "remote-refs",
                    "external_entity",
                    "xslt_document",
                    f"XSLT document() external ref: {m.group(1)}",
                    m.group(1),
                    "regex",
                    Severity.HIGH,
                    0.7,
                )
            )
    return findings


def c_archive(
    rec: FileRecord,
    logger: RunLogger,
    max_depth: int,
    enable_specialized: bool,
    depth: int,
) -> list[Finding]:
    findings: list[Finding] = []

    # Check if ZIP has encrypted members
    if rec.path.lower().endswith(".zip") or _is_zip(rec.path):
        try:
            with zipfile.ZipFile(rec.path) as z:
                for info in z.infolist():
                    if info.flag_bits & 0x1:
                        findings.append(
                            Finding.from_file_record(
                                rec,
                                "remote-refs",
                                "encrypted_file",
                                "zip_encrypt",
                                "Archive member is encrypted / password-protected",
                                info.filename,
                                "zipfile",
                                Severity.MEDIUM,
                                0.9,
                            )
                        )
                        return findings
        except Exception as e:
            err_msg = str(e).lower()
            if "encrypted" in err_msg or "password" in err_msg:
                findings.append(
                    Finding.from_file_record(
                        rec,
                        "remote-refs",
                        "encrypted_file",
                        "zip_encrypt_error",
                        f"Archive decryption failed: {e}",
                        str(e),
                        "zipfile",
                        Severity.MEDIUM,
                        0.9,
                    )
                )
                return findings

    members = _list_archive_members(rec.path, logger)
    if not members:
        return findings
    findings.append(
        Finding.from_file_record(
            rec,
            "remote-refs",
            "archive_nested",
            "archive",
            f"Archive contains {len(members)} members requiring recursion",
            str(members[:10]),
            "canary-scan",
            Severity.INFO,
            0.5,
            extras={"member_count": len(members), "depth": depth},
        )
    )
    if depth >= max_depth:
        return findings
    tmp_root = Path(rec.path).parent / f".canary-scan-extract-{Path(rec.path).name}-{depth}"
    extracted = _extract_archive(rec.path, tmp_root, logger)
    from canary_scan.lib.type_detect import detect_bucket, extension_of

    for mpath in extracted:
        ext = extension_of(mpath)
        mime = _quick_mime(mpath)
        bucket = detect_bucket(mpath, mime, enable_specialized=enable_specialized)
        sub_rec = FileRecord(
            path=mpath,
            sha256="",
            size=0,
            mtime="",
            mime=mime,
            bucket=bucket.value,
            extension=ext,
        )
        sub_findings = route(sub_rec, bucket, logger, max_depth, enable_specialized, depth + 1)
        for sf in sub_findings:
            sf.file = f"{rec.path}!/{mpath}"
            findings.append(sf)
    return findings


def _read_text(path: str) -> str:
    try:
        p = Path(path)
        if p.stat().st_size > 50 * 1024 * 1024:
            return ""
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _read_bytes(path: str) -> bytes:
    try:
        p = Path(path)
        if p.stat().st_size > 50 * 1024 * 1024:
            return b""
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return b""


def _tag_for_url(raw: str, url: str) -> str:
    idx = raw.find(url)
    if idx < 0:
        return ""
    before = raw[:idx].rsplit("<", 1)
    if len(before) == 2:
        tag = before[1].split(">", 1)[0].split()[0] if before[1] else ""
        return tag.lower().strip("/")
    return ""


def _is_tracking_pixel(raw: str, url: str) -> bool:
    m = re.search(r"<img[^>]*src\s*=\s*[\"']" + re.escape(url) + r"[\"'][^>]*>", raw, re.IGNORECASE)
    if not m:
        return False
    tag = m.group(0).lower()
    return (
        'width="1"' in tag
        or "width='1'" in tag
        or "width=1" in tag
        or 'height="1"' in tag
        or "height='1'" in tag
        or "height=1" in tag
    )


def _list_archive_members(path: str, logger: RunLogger) -> list[str]:
    try:
        if path.endswith(".zip") or _is_zip(path):
            with zipfile.ZipFile(path) as z:
                return z.namelist()
        if path.endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(path) as t:
                return t.getnames()
    except Exception as e:
        logger.log(f"archive list error {path}: {e}")
    return []


def _is_zip(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"PK\x03\x04"
    except OSError:
        return False


def _safe_zip_members(zip_file: zipfile.ZipFile, dest: Path) -> list[zipfile.ZipInfo]:
    safe_members = []
    resolved_dest = dest.resolve()
    for info in zip_file.infolist():
        target_path = (dest / info.filename).resolve()
        if resolved_dest in target_path.parents or target_path == resolved_dest:
            safe_members.append(info)
    return safe_members


def _safe_tar_members(tar_file: tarfile.TarFile, dest: Path) -> list[tarfile.TarInfo]:
    safe_members = []
    resolved_dest = dest.resolve()
    for info in tar_file.getmembers():
        target_path = (dest / info.name).resolve()
        if resolved_dest in target_path.parents or target_path == resolved_dest:
            safe_members.append(info)
    return safe_members


def _extract_archive(path: str, dest: Path, logger: RunLogger) -> list[str]:
    dest.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    try:
        if _is_zip(path):
            with zipfile.ZipFile(path) as z:
                safe_members = _safe_zip_members(z, dest)
                z.extractall(dest, members=safe_members)
                extracted = [str(dest / n.filename) for n in safe_members if not n.filename.endswith("/")]
        elif path.endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(path) as t:
                safe_members = _safe_tar_members(t, dest)
                t.extractall(dest, members=safe_members)
                extracted = [str(dest / m.name) for m in safe_members if m.isfile()]
        else:
            result = safe_subprocess(["7z", "x", f"-o{dest}", "-y", "--", path], logger=logger, timeout=120)
            if result.returncode == 0:
                resolved_dest = dest.resolve()
                for root, _, names in os.walk(dest):
                    for n in names:
                        full_path = Path(root) / n
                        resolved_path = full_path.resolve()
                        if resolved_dest in resolved_path.parents or resolved_path == resolved_dest:
                            extracted.append(str(resolved_path))
    except Exception as e:
        logger.log(f"archive extract error {path}: {e}")
    return extracted


def _quick_mime(path: str) -> str:
    result = safe_subprocess(["file", "-b", "--", path], timeout=10)
    return result.stdout.strip() if result.returncode == 0 else ""


def c_lnk(rec: FileRecord, logger: RunLogger) -> list[Finding]:
    findings: list[Finding] = []
    try:
        import pylnk

        lnk = pylnk.open(rec.path)

        local_path = getattr(lnk, "local_path", None)
        if local_path:
            findings.extend(_scan_raw_text(rec, local_path, "pylnk", "lnk_local_path", Severity.HIGH, 0.8))

        network_path = getattr(lnk, "network_path", None)
        if network_path:
            findings.extend(_scan_raw_text(rec, network_path, "pylnk", "lnk_network_path", Severity.CRITICAL, 0.9))

        target_path = getattr(lnk, "path", None)
        if target_path:
            findings.extend(_scan_raw_text(rec, target_path, "pylnk", "lnk_path", Severity.HIGH, 0.8))

    except Exception as e:
        logger.log(f"Error parsing .lnk file {rec.path}: {e}")
    return findings
