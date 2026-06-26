"""Data models: Finding, FileRecord, Severity."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from canary_scan.lib.config import TOOL_NAME, TOOL_VERSION, Bucket, Severity


@dataclass
class FileRecord:
    path: str
    sha256: str
    size: int
    mtime: str
    mime: str
    bucket: Bucket
    extension: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.bucket, Bucket):
            self.bucket = Bucket(self.bucket)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["bucket"] = self.bucket.value
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> FileRecord:
        for field_name in ("path", "sha256", "size", "mtime", "mime", "bucket"):
            if field_name not in d:
                raise TypeError(f"Missing required field in FileRecord dictionary: {field_name}")
        return cls(
            path=str(d["path"]),
            sha256=str(d["sha256"]),
            size=int(d["size"]),
            mtime=str(d["mtime"]),
            mime=str(d["mime"]),
            bucket=Bucket(d["bucket"]),
            extension=str(d.get("extension", "")),
        )


@dataclass
class Finding:
    file: str
    sha256: str
    file_type: str
    bucket: Bucket
    stage: str
    category: str
    subcategory: str
    finding: str
    evidence: str
    tool: str
    severity: str
    confidence: float = 0.0
    extras: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.bucket, Bucket):
            self.bucket = Bucket(self.bucket)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "sha256": self.sha256,
            "file_type": self.file_type,
            "bucket": self.bucket.value,
            "stage": self.stage,
            "category": self.category,
            "subcategory": self.subcategory,
            "finding": self.finding,
            "evidence": self.evidence,
            "tool": self.tool,
            "severity": self.severity,
            "confidence": self.confidence,
            "extras": self.extras,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        for field_name in (
            "file",
            "sha256",
            "file_type",
            "bucket",
            "stage",
            "category",
            "subcategory",
            "finding",
            "evidence",
            "tool",
        ):
            if field_name not in d:
                raise TypeError(f"Missing required field in Finding dictionary: {field_name}")
        return cls(
            file=str(d["file"]),
            sha256=str(d.get("sha256", "")),
            file_type=str(d.get("file_type", "")),
            bucket=Bucket(d["bucket"]),
            stage=str(d.get("stage", "")),
            category=str(d.get("category", "")),
            subcategory=str(d.get("subcategory", "")),
            finding=str(d.get("finding", "")),
            evidence=str(d.get("evidence", "")),
            tool=str(d.get("tool", "")),
            severity=str(d.get("severity", "info")),
            confidence=float(d.get("confidence", 0.0)),
            extras=dict(d.get("extras", {})),
        )

    def to_csv_row(self) -> dict[str, Any]:
        d = self.to_dict()
        d["extras_json"] = json.dumps(d.pop("extras", {}), ensure_ascii=False)
        return d

    @staticmethod
    def csv_columns() -> list[str]:
        return [
            "file",
            "sha256",
            "file_type",
            "bucket",
            "stage",
            "category",
            "subcategory",
            "finding",
            "evidence",
            "tool",
            "severity",
            "confidence",
            "extras_json",
        ]

    @staticmethod
    def from_file_record(
        rec: FileRecord,
        stage: str,
        category: str,
        subcategory: str,
        finding: str,
        evidence: str,
        tool: str,
        severity: Severity,
        confidence: float = 0.0,
        extras: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(
            file=rec.path,
            sha256=rec.sha256,
            file_type=rec.extension or rec.bucket.value,
            bucket=rec.bucket,
            stage=stage,
            category=category,
            subcategory=subcategory,
            finding=finding,
            evidence=evidence,
            tool=tool,
            severity=severity.value,
            confidence=confidence,
            extras=extras or {},
        )


def make_info_finding(rec: FileRecord, stage: str, message: str) -> Finding:
    return Finding.from_file_record(
        rec,
        stage=stage,
        category="no_bucket_check",
        subcategory="",
        finding=message,
        evidence="",
        tool=TOOL_NAME,
        severity=Severity.INFO,
        confidence=0.0,
    )


def tool_info() -> dict[str, str]:
    return {"name": TOOL_NAME, "version": TOOL_VERSION}
