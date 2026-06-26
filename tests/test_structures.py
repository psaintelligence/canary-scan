import pytest

from canary_scan.lib.config import Bucket
from canary_scan.lib.models import FileRecord, Finding
from canary_scan.lib.orchestrator import PipelineContext, Stage, StageRegistry


def test_stage_registry_custom_registration():
    @StageRegistry.register("test-dummy-stage")
    class DummyStage(Stage):
        def run(self, ctx: PipelineContext) -> None:
            ctx.args["dummy_called"] = True

    stage_cls = StageRegistry.get_stage("test-dummy-stage")
    assert stage_cls is DummyStage
    assert stage_cls.name == "test-dummy-stage"


def test_file_record_coercion_and_validation():
    # Coercion from string to Bucket enum
    rec = FileRecord(
        path="foo/bar.pdf",
        sha256="abc",
        size=10,
        mtime="2026",
        mime="application/pdf",
        bucket="pdf",  # string type
    )
    assert rec.bucket == Bucket.PDF

    # Serializing
    d = rec.to_dict()
    assert d["bucket"] == "pdf"

    # Deserializing
    rec2 = FileRecord.from_dict(d)
    assert rec2.bucket == Bucket.PDF
    assert rec2.path == "foo/bar.pdf"

    # Missing field raises TypeError
    bad_dict = d.copy()
    bad_dict.pop("sha256")
    with pytest.raises(TypeError) as excinfo:
        FileRecord.from_dict(bad_dict)
    assert "Missing required field" in str(excinfo.value)


def test_finding_coercion_and_validation():
    finding_dict = {
        "file": "foo/bar.pdf",
        "sha256": "abc",
        "file_type": "pdf",
        "bucket": "pdf",
        "stage": "metadata",
        "category": "active_url",
        "subcategory": "creator",
        "finding": "Found url",
        "evidence": "http://google.com",
        "tool": "exiftool",
        "severity": "high",
        "confidence": 0.8,
        "extras": {},
    }

    # Deserializing validation
    f = Finding.from_dict(finding_dict)
    assert f.bucket == Bucket.PDF
    assert f.confidence == 0.8

    # Serializing
    d = f.to_dict()
    assert d["bucket"] == "pdf"

    # Missing field raises TypeError
    bad_dict = finding_dict.copy()
    bad_dict.pop("finding")
    with pytest.raises(TypeError) as excinfo:
        Finding.from_dict(bad_dict)
    assert "Missing required field" in str(excinfo.value)
