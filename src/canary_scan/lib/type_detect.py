"""File-type detection: maps file(1) output and extensions to buckets."""

from __future__ import annotations

from pathlib import Path

from canary_scan.lib.config import EXTENSION_BUCKETS, SPECIALIZED_BUCKETS, SPECIALIZED_EXTENSIONS, Bucket


def detect_bucket(file_path: str, mime: str = "", enable_specialized: bool = False) -> Bucket:
    ext = Path(file_path).suffix.lower()
    if enable_specialized and ext in SPECIALIZED_EXTENSIONS:
        return Bucket.SPECIALIZED
    if ext in EXTENSION_BUCKETS:
        return EXTENSION_BUCKETS[ext]
    lowered_mime = mime.lower()
    if "pdf" in lowered_mime:
        return Bucket.PDF
    if "rich text format" in lowered_mime or "rtf" in lowered_mime:
        return Bucket.RTF
    if "composite document file" in lowered_mime:
        return Bucket.OLE
    if "zip archive" in lowered_mime:
        return Bucket.ARCHIVE
    if "tar archive" in lowered_mime or "gzip" in lowered_mime:
        return Bucket.ARCHIVE
    if "jpeg" in lowered_mime or "png" in lowered_mime or "gif" in lowered_mime:
        return Bucket.IMAGE
    if "html" in lowered_mime:
        return Bucket.HTML
    if "csv" in lowered_mime:
        return Bucket.CSV
    if "xml" in lowered_mime:
        return Bucket.XML
    return Bucket.OTHER


def detect_specialized_subtype(file_path: str) -> str:
    ext = Path(file_path).suffix.lower()
    return SPECIALIZED_BUCKETS.get(ext, "unknown")


def extension_of(file_path: str) -> str:
    return Path(file_path).suffix.lower()
