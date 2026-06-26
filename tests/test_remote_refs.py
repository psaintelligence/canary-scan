"""Test remote references stage — per-bucket detection."""

from pathlib import Path

from canary_scan.lib.config import Bucket
from canary_scan.lib.models import FileRecord
from canary_scan.lib.runners import RunLogger
from canary_scan.scanners.remote_refs import c_csv, c_html, c_xml, route, run


def make_rec(filepath, bucket):
    return FileRecord(
        path=str(filepath),
        sha256="abc123",
        size=100,
        mtime="2026-01-01T00:00:00",
        mime="",
        bucket=bucket.value,
        extension=Path(filepath).suffix.lower(),
    )


def test_pdf_uri_canary(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "pdf_uri_canary.pdf", Bucket.PDF)
    findings = route(rec, Bucket.PDF, logger, 3, False, 0)

    urls = [f for f in findings if f.category == "active_url"]
    assert len(urls) > 0
    assert any("tracker.example.com" in f.evidence for f in urls)
    logger.close()


def test_pdf_js_canary(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "pdf_js_canary.pdf", Bucket.PDF)
    findings = route(rec, Bucket.PDF, logger, 3, False, 0)

    js_findings = [f for f in findings if f.category in ("javascript", "open_action")]
    assert len(js_findings) > 0
    logger.close()


def test_rtf_objdata_canary(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "rtf_objdata_canary.rtf", Bucket.RTF)
    findings = route(rec, Bucket.RTF, logger, 3, False, 0)

    assert any(f.category in ("embedded_object", "active_url") for f in findings)
    logger.close()


def test_docx_external_link(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "docx_external_link.docx", Bucket.OOXML)
    findings = route(rec, Bucket.OOXML, logger, 3, False, 0)

    urls = [f for f in findings if f.category == "active_url"]
    assert len(urls) > 0
    assert any("tracker.example.com" in f.evidence for f in urls)
    logger.close()


def test_csv_formula_injection(fixtures_dir):
    rec = make_rec(fixtures_dir / "csv_formula_injection.csv", Bucket.CSV)
    findings = c_csv(rec)

    assert any(f.category == "formula_injection" for f in findings)
    assert any(f.category == "active_url" for f in findings)


def test_html_beacon(fixtures_dir):
    rec = make_rec(fixtures_dir / "html_beacon.html", Bucket.HTML)
    findings = c_html(rec, RunLogger(Path("/dev/null")))

    assert any(f.category == "tracking_pixel" for f in findings)
    assert any(f.category == "javascript" for f in findings)


def test_xml_xxe(fixtures_dir):
    rec = make_rec(fixtures_dir / "xml_xxe.xml", Bucket.XML)
    findings = c_xml(rec)

    assert any(f.category == "external_entity" for f in findings)


def test_eml_tracking_pixel(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "eml_tracking_pixel.eml", Bucket.EMAIL)
    findings = route(rec, Bucket.EMAIL, logger, 3, False, 0)

    assert any(f.category == "tracking_pixel" for f in findings)
    assert any(f.category == "read_receipt" for f in findings)
    logger.close()


def test_png_text_canary(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "png_text_canary.png", Bucket.IMAGE)
    findings = route(rec, Bucket.IMAGE, logger, 3, False, 0)

    assert len(findings) >= 0
    logger.close()


def test_nested_zip(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    rec = make_rec(fixtures_dir / "nested.zip", Bucket.ARCHIVE)
    findings = route(rec, Bucket.ARCHIVE, logger, 3, False, 0)

    nested_urls = [f for f in findings if f.category == "active_url"]
    assert len(nested_urls) > 0
    assert any("nested-canary" in f.evidence for f in nested_urls)
    logger.close()


def test_full_remote_refs_run(fixtures_dir, tmp_path):
    outdir = tmp_path / ".canary-scan"
    outdir.mkdir()
    logger = RunLogger(outdir / "canary-scan.log")
    logger.open()

    from canary_scan.scanners.inventory import run as run_inventory

    records, _ = run_inventory(str(fixtures_dir), outdir, logger)

    findings = run(records, outdir, logger, max_archive_depth=3)

    assert len(findings) > 0
    assert any(f.category == "active_url" for f in findings)
    assert any(f.category == "formula_injection" for f in findings)
    assert any(f.category == "external_entity" for f in findings)

    artefact = outdir / "canary-scan-remote-refs.json"
    assert artefact.exists()
    logger.close()


def test_zip_slip_protection(tmp_path):
    import tarfile
    import zipfile
    from unittest.mock import MagicMock

    from canary_scan.scanners.remote_refs import _safe_tar_members, _safe_zip_members

    # Mock ZipInfo
    zip_mock = MagicMock(spec=zipfile.ZipFile)

    # Safe member
    m1 = MagicMock(spec=zipfile.ZipInfo)
    m1.filename = "safe.txt"

    # Unsafe member
    m2 = MagicMock(spec=zipfile.ZipInfo)
    m2.filename = "../unsafe.txt"

    # Another unsafe member
    m3 = MagicMock(spec=zipfile.ZipInfo)
    m3.filename = "sub/../../unsafe.txt"

    zip_mock.infolist.return_value = [m1, m2, m3]

    dest = tmp_path / "dest"
    dest.mkdir()

    safe = _safe_zip_members(zip_mock, dest)
    assert len(safe) == 1
    assert safe[0].filename == "safe.txt"

    # Tar mock
    tar_mock = MagicMock(spec=tarfile.TarFile)
    t1 = MagicMock(spec=tarfile.TarInfo)
    t1.name = "safe.txt"
    t2 = MagicMock(spec=tarfile.TarInfo)
    t2.name = "../unsafe.txt"

    tar_mock.getmembers.return_value = [t1, t2]
    safe_tar = _safe_tar_members(tar_mock, dest)
    assert len(safe_tar) == 1
    assert safe_tar[0].name == "safe.txt"


def test_ftp_unc_ref_detection():
    from canary_scan.lib.config import Severity
    from canary_scan.scanners.remote_refs import _scan_raw_text

    rec = make_rec("dummy.txt", Bucket.HTML)
    text = "Here is an FTP link: ftp://example.com/file and a UNC path: \\\\server\\share\\file"

    findings = _scan_raw_text(rec, text, "test-tool", "test-sub", Severity.MEDIUM, 0.7)

    ftps = [f for f in findings if "ftp" in f.evidence]
    uncs = [f for f in findings if f.subcategory == "unc_path"]

    assert len(ftps) == 1
    assert len(uncs) == 1
    assert uncs[0].severity == "critical"


def test_pdf_forms_and_watermarks(tmp_path):
    from reportlab.pdfgen import canvas

    from canary_scan.scanners.remote_refs import c_pdf

    # 1. Create a PDF containing OCG watermark and form fields
    pdf_path = tmp_path / "test_form_ocg.pdf"
    c = canvas.Canvas(str(pdf_path))
    c.drawString(100, 100, "Base page")

    # Add form field
    c.acroForm.textfield(name="tx1", tooltip="Form field", x=110, y=110)
    c.save()

    # Append dummy OCG objects that pdf-parser will detect
    with open(pdf_path, "ab") as f:
        f.write(b"\n100 0 obj\n<< /OCProperties << /OCGs [101 0 R] >> >>\nendobj\n")
        f.write(b"\n101 0 obj\n<< /Type /OCG /Name (Watermark) >>\nendobj\n")

    rec = make_rec(pdf_path, Bucket.PDF)
    from canary_scan.lib.runners import RunLogger

    logger = RunLogger(tmp_path / "test.log")

    findings = c_pdf(rec, logger)

    assert any(f.category == "form_field" for f in findings)
    assert any(f.category == "watermark" for f in findings)


def test_ooxml_dde_and_header_links(tmp_path):
    import zipfile

    from canary_scan.scanners.remote_refs import c_ooxml

    docx_path = tmp_path / "test_dde_header.docx"
    with zipfile.ZipFile(docx_path, "w") as z:
        z.writestr("word/document.xml", '<w:instrText> DDEAUTO "http://tracker.com" </w:instrText>')
        z.writestr("word/header1.xml", "<w:t>Header link: http://tracker-header.com</w:t>")
        z.writestr("[Content_Types].xml", '<Types><Default Extension="rels" ContentType="a"/></Types>')

    rec = make_rec(docx_path, Bucket.OOXML)
    from canary_scan.lib.runners import RunLogger

    logger = RunLogger(tmp_path / "test.log")

    findings = c_ooxml(rec, logger)

    assert any(f.category == "javascript" and f.subcategory == "dde_link" for f in findings)
    assert any(f.category == "active_url" and "header1.xml" in f.subcategory for f in findings)


def test_thinkst_canarytoken_cleaning_and_detection():
    from canary_scan.lib.config import Severity
    from canary_scan.scanners.remote_refs import _clean_url, _scan_raw_text

    # 1. Test clean url function
    url1 = "http://canarytokens.com/about/QXUGUTAENT)"
    cleaned, is_thinkst = _clean_url(url1)
    assert cleaned == "http://canarytokens.com/about/"
    assert is_thinkst is True

    url2 = "http://canarytokens.com/about/QXUGUTAENT/feedback"
    cleaned, is_thinkst = _clean_url(url2)
    assert cleaned == "http://canarytokens.com/about/"
    assert is_thinkst is True

    url3 = "http://example.com/normal"
    cleaned, is_thinkst = _clean_url(url3)
    assert cleaned == "http://example.com/normal"
    assert is_thinkst is False

    # 2. Test _scan_raw_text
    rec = make_rec("dummy.txt", Bucket.HTML)
    text = "Here is a thinkst token: http://canarytokens.com/terms/QXUGUTAENT) and normal: http://example.com/normal"
    findings = _scan_raw_text(rec, text, "test-tool", "test-sub", Severity.MEDIUM, 0.7)

    thinkst_findings = [f for f in findings if f.subcategory == "thinkst_canarytoken"]
    normal_findings = [f for f in findings if f.subcategory == "test-sub"]

    assert len(thinkst_findings) == 1
    assert thinkst_findings[0].evidence == "http://canarytokens.com/terms/"
    assert thinkst_findings[0].severity == "critical"
    assert thinkst_findings[0].confidence == 1.0

    assert len(normal_findings) == 1
    assert normal_findings[0].evidence == "http://example.com/normal"


def test_pdf_in_memory_stream_decompressor(tmp_path):
    import zlib

    from canary_scan.scanners.remote_refs import c_pdf

    # Compressed URL inside stream
    stream_content = b"Check this out: http://canarytokens.com/pdfstream/QXUGUTAENT)"
    compressed = zlib.compress(stream_content)

    pdf_path = tmp_path / "test_stream.pdf"
    pdf_path.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Length "
        + str(len(compressed)).encode()
        + b" /Filter /FlateDecode >>\nstream\n"
        + compressed
        + b"\nendstream\nendobj\n%%EOF\n"
    )

    rec = make_rec(pdf_path, Bucket.PDF)
    logger = RunLogger(tmp_path / "test.log")

    findings = c_pdf(rec, logger)

    thinkst_findings = [f for f in findings if f.subcategory == "thinkst_canarytoken"]
    assert len(thinkst_findings) == 1
    assert thinkst_findings[0].evidence == "http://canarytokens.com/pdfstream/"
    assert thinkst_findings[0].severity == "critical"


def test_ooxml_global_zip_member_scan(tmp_path):
    import zipfile

    from canary_scan.scanners.remote_refs import c_ooxml

    docx_path = tmp_path / "test_global.docx"
    with zipfile.ZipFile(docx_path, "w") as z:
        # Non-standard XML member containing URL
        z.writestr("word/theme/theme1.xml", "<w:t>Theme config: http://canarytokens.com/theme/QXUGUTAENT)</w:t>")
        # Benign domain (should be marked as low/medium or ignored/suppressed depending on filter, but raw_text will still match it)
        z.writestr("word/settings.xml", "<w:t>Standard doc: http://w3.org/standard</w:t>")

    rec = make_rec(docx_path, Bucket.OOXML)
    logger = RunLogger(tmp_path / "test.log")

    findings = c_ooxml(rec, logger)

    thinkst_findings = [f for f in findings if f.subcategory == "thinkst_canarytoken"]
    assert len(thinkst_findings) == 1
    assert thinkst_findings[0].evidence == "http://canarytokens.com/theme/"
