"""Tests for recently added missing detection techniques."""

import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from canary_scan.lib.config import Bucket
from canary_scan.lib.models import FileRecord
from canary_scan.lib.runners import RunLogger
from canary_scan.scanners.remote_refs import c_archive, c_html, c_lnk, c_ole, c_ooxml, c_pdf
from canary_scan.scanners.stego import scan_image
from canary_scan.scanners.uniqueness import _diff_pdfs


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


def test_pdf_incremental_updates(tmp_path):
    pdf_path = tmp_path / "incremental.pdf"
    # Write a PDF with multiple %%EOF markers
    pdf_path.write_bytes(b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n%%EOF\n2 0 obj\n<< >>\nendobj\n%%EOF\n")

    rec = make_rec(pdf_path, Bucket.PDF)
    logger = RunLogger(tmp_path / "test.log")
    findings = c_pdf(rec, logger)

    inc_findings = [f for f in findings if f.category == "incremental_update"]
    assert len(inc_findings) == 1
    assert "incremental" in inc_findings[0].finding


def test_pdf_encrypted_detection(tmp_path):
    pdf_path = tmp_path / "encrypted.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

    rec = make_rec(pdf_path, Bucket.PDF)
    logger = RunLogger(tmp_path / "test.log")

    # Mock pdfid output to include /Encrypt 1
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "  /Encrypt 1\n  /JS 0\n"
    mock_res.stderr = ""

    with patch("canary_scan.lib.runners.subprocess.run", return_value=mock_res):
        findings = c_pdf(rec, logger)

    enc_findings = [f for f in findings if f.category == "encrypted_file"]
    assert len(enc_findings) == 1
    assert "encrypted" in enc_findings[0].finding


def test_encrypted_zip_detection(tmp_path):
    zip_path = tmp_path / "encrypted.zip"
    with zipfile.ZipFile(zip_path, "w") as z:
        z.writestr("test.txt", "dummy content")

    rec = make_rec(zip_path, Bucket.ARCHIVE)
    logger = RunLogger(tmp_path / "test.log")

    mock_info = MagicMock()
    mock_info.filename = "secret.txt"
    mock_info.flag_bits = 1

    with patch("zipfile.ZipFile.infolist", return_value=[mock_info]):
        findings = c_archive(rec, logger, 3, False, 0)

    enc_findings = [f for f in findings if f.category == "encrypted_file"]
    assert len(enc_findings) == 1


def test_ooxml_content_type_injection(tmp_path):
    docx_path = tmp_path / "injection.docx"
    with zipfile.ZipFile(docx_path, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0" encoding="UTF-8"?><Types><Type Target="http://tracker.com/pixel.png"/></Types>',
        )

    rec = make_rec(docx_path, Bucket.OOXML)
    logger = RunLogger(tmp_path / "test.log")

    findings = c_ooxml(rec, logger)
    urls = [f for f in findings if f.category == "active_url"]
    assert len(urls) > 0
    assert any("tracker.com" in f.evidence for f in urls)


def test_lnk_shortcut_analysis(tmp_path):
    lnk_path = tmp_path / "shortcut.lnk"
    lnk_path.touch()

    rec = make_rec(lnk_path, Bucket.OTHER)
    logger = RunLogger(tmp_path / "test.log")

    mock_lnk = MagicMock()
    mock_lnk.local_path = "C:\\Windows\\System32\\cmd.exe"
    mock_lnk.network_path = "\\\\malicious-server\\share\\callback"
    mock_lnk.path = "C:\\target"

    with patch("pylnk.open", return_value=mock_lnk):
        findings = c_lnk(rec, logger)

    uncs = [f for f in findings if f.subcategory == "unc_path"]
    assert len(uncs) == 1
    assert "malicious-server" in uncs[0].evidence


def test_mhtml_parser(tmp_path):
    mhtml_path = tmp_path / "test.mhtml"
    mhtml_content = (
        "MIME-Version: 1.0\n"
        'Content-Type: multipart/related; boundary="boundary-1"\n\n'
        "--boundary-1\n"
        "Content-Type: text/html\n"
        "Content-Location: http://tracker-location.com/main.html\n\n"
        '<html><body><img src="http://tracker.com/pixel.gif" width="1" height="1"></body></html>\n'
        "--boundary-1--\n"
    )
    mhtml_path.write_text(mhtml_content, encoding="utf-8")

    rec = make_rec(mhtml_path, Bucket.HTML)
    logger = RunLogger(tmp_path / "test.log")

    findings = c_html(rec, logger)

    loc_findings = [f for f in findings if f.subcategory == "part_content_location"]
    body_findings = [f for f in findings if f.subcategory == "part_body"]

    assert len(loc_findings) > 0
    assert len(body_findings) > 0
    assert any("tracker-location.com" in f.evidence for f in loc_findings)
    assert any("tracker.com" in f.evidence for f in body_findings)


def test_pdf_pixel_diffing(tmp_path):
    logger = RunLogger(tmp_path / "test.log")

    pdf1 = make_rec(tmp_path / "pdf1.pdf", Bucket.PDF)
    pdf2 = make_rec(tmp_path / "pdf2.pdf", Bucket.PDF)
    pdf1.sha256 = "11111111111111111111111111111111"
    pdf2.sha256 = "22222222222222222222222222222222"

    # We mock qpdf subprocess to return 0 and write identical content
    # We mock mutool subprocess to write different content for each PDF
    from canary_scan.lib.runners import subprocess

    original_run = subprocess.run

    def mock_run(args, **kwargs):
        if "qpdf" in args:
            out_file = args[-1]
            Path(out_file).write_text("identical normalized body", encoding="utf-8")
            res = MagicMock()
            res.returncode = 0
            return res
        if "mutool" in args:
            out_file = args[3]
            if "11111" in out_file:
                Path(out_file).write_bytes(b"rendered_page_1")
            else:
                Path(out_file).write_bytes(b"rendered_page_2")
            res = MagicMock()
            res.returncode = 0
            return res
        return original_run(args, **kwargs)

    with patch("canary_scan.lib.runners.subprocess.run", side_effect=mock_run):
        diffs = _diff_pdfs([pdf1, pdf2], tmp_path, logger)

    pixel_diffs = [d for d in diffs if d.field == "pdf_pixel_diff"]
    assert len(pixel_diffs) == 1
    assert "visually" in pixel_diffs[0].description


def test_ole_hyperlinks(tmp_path):
    ole_path = tmp_path / "test.ole"
    ole_path.write_bytes(b"dummy ole content")

    rec = make_rec(ole_path, Bucket.OLE)
    logger = RunLogger(tmp_path / "test.log")

    mock_ole = MagicMock()
    mock_ole.listdir.return_value = [["\x01Ole"], ["\x03ObjInfo"]]

    mock_stream1 = MagicMock()
    mock_stream1.read.return_value = b"Contains a link: http://tracker.com/callback"
    mock_stream2 = MagicMock()
    mock_stream2.read.return_value = b"Another link: ftp://example.com/ftp_callback"

    def mock_openstream(name):
        if name == ["\x01Ole"]:
            return mock_stream1
        return mock_stream2

    mock_ole.openstream.side_effect = mock_openstream
    mock_ole.__enter__.return_value = mock_ole

    with patch("canary_scan.scanners.remote_refs.safe_subprocess") as mock_subproc:
        mock_subproc.return_value.returncode = 0
        mock_subproc.return_value.stdout = ""
        mock_subproc.return_value.stderr = ""

        with patch("olefile.isOleFile", return_value=True), patch("olefile.OleFileIO", return_value=mock_ole):
            findings = c_ole(rec, logger)

    urls = [f for f in findings if f.category == "active_url"]
    assert len(urls) >= 2
    assert any("tracker.com" in f.evidence for f in urls)
    assert any("ftp://example.com" in f.evidence for f in urls)


def test_exif_thumbnail_mismatch(tmp_path):
    img_path = tmp_path / "image.jpg"
    img_path.write_bytes(b"dummy image bytes")

    rec = make_rec(img_path, Bucket.IMAGE)
    logger = RunLogger(tmp_path / "test.log")

    import io

    from PIL import Image

    main_img = Image.new("RGB", (800, 600), color="blue")
    main_img.save(img_path)

    thumb_img = Image.new("RGB", (100, 100), color="red")
    thumb_io = io.BytesIO()
    thumb_img.save(thumb_io, format="JPEG")
    thumb_bytes = thumb_io.getvalue()

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = thumb_bytes

    with patch("canary_scan.lib.runners.subprocess.run", return_value=mock_res):
        findings = scan_image(rec, logger, None)

    mismatches = [f for f in findings if f.subcategory == "thumbnail_mismatch"]
    assert len(mismatches) == 1
    assert "Hamming" in mismatches[0].evidence


def test_pdf_form_field_metadata_extraction(tmp_path):
    from reportlab.pdfgen import canvas

    from canary_scan.scanners.metadata import _process_record

    pdf_path = tmp_path / "test_form_metadata.pdf"
    c = canvas.Canvas(str(pdf_path))
    c.drawString(100, 100, "Base page")
    c.acroForm.textfield(name="tx1", tooltip="http://tracker-form.com/callback", x=110, y=110)
    c.save()

    rec = make_rec(pdf_path, Bucket.PDF)
    logger = RunLogger(tmp_path / "test.log")

    from canary_scan.lib.runners import subprocess

    original_run = subprocess.run

    def mock_run(args, **kwargs):
        if "exiftool" in args:
            res = MagicMock()
            res.returncode = 0
            res.stdout = '[{"SourceFile": "test.pdf", "FileType": "PDF", "PageCount": 1}]'
            res.stderr = ""
            return res
        return original_run(args, **kwargs)

    with patch("canary_scan.lib.runners.subprocess.run", side_effect=mock_run):
        path, fields, findings = _process_record(rec, logger)

    assert fields is not None
    assert "FormFields" in fields
    assert len(fields["FormFields"]) == 1
    assert fields["FormFields"][0]["t"] == "tx1"
    assert fields["FormFields"][0]["tu"] == "http://tracker-form.com/callback"

    active_urls = [f for f in findings if f.category == "active_url"]
    assert len(active_urls) == 1
    assert active_urls[0].evidence == "http://tracker-form.com/callback"
    assert "pdf_form_tooltip" in active_urls[0].subcategory


def test_pdf_form_field_uniqueness(tmp_path):
    from canary_scan.scanners.uniqueness import _diff_pdfs

    pdf1 = make_rec(tmp_path / "pdf1.pdf", Bucket.PDF)
    pdf2 = make_rec(tmp_path / "pdf2.pdf", Bucket.PDF)
    pdf1.sha256 = "111111111111"
    pdf2.sha256 = "222222222222"

    metadata = {
        str(pdf1.path): {"FormFields": [{"obj": "6 0", "ft": "/Tx", "t": "tx1", "tu": "tool1", "v": "value1"}]},
        str(pdf2.path): {"FormFields": [{"obj": "6 0", "ft": "/Tx", "t": "tx1", "tu": "tool1", "v": "value2"}]},
    }

    logger = RunLogger(tmp_path / "test.log")

    from canary_scan.lib.runners import subprocess

    original_run = subprocess.run

    def mock_run(args, **kwargs):
        if "qpdf" in args:
            out_file = args[-1]
            Path(out_file).write_text("identical normalized body", encoding="utf-8")
            res = MagicMock()
            res.returncode = 0
            return res
        return original_run(args, **kwargs)

    with patch("canary_scan.lib.runners.subprocess.run", side_effect=mock_run):
        diffs = _diff_pdfs([pdf1, pdf2], tmp_path, logger, metadata)

    form_diffs = [d for d in diffs if d.field == "pdf_form_field"]
    assert len(form_diffs) == 1
    assert "value1" in form_diffs[0].evidence
    assert "value2" in form_diffs[0].evidence
