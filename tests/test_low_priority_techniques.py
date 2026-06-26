"""Tests for recently added low priority / specialized detection techniques."""

import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from canary_scan.lib.config import Bucket
from canary_scan.lib.models import FileRecord
from canary_scan.lib.runners import RunLogger
from canary_scan.scanners.remote_refs import c_email, c_ole, c_ooxml, c_pdf
from canary_scan.scanners.stego import scan_image
from canary_scan.scanners.uniqueness import _diff_text


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


def test_pdf_signature_detection(tmp_path):
    pdf_path = tmp_path / "signed.pdf"
    pdf_path.write_bytes(b"%PDF-1.4\n%%EOF\n")

    rec = make_rec(pdf_path, Bucket.PDF)
    logger = RunLogger(tmp_path / "test.log")

    # We mock pdf_parser subprocess run to return /Sig
    from canary_scan.lib.runners import subprocess

    original_run = subprocess.run

    def mock_run(args, **kwargs):
        if any("pdf_parser" in str(arg) for arg in args):
            res = MagicMock()
            res.returncode = 0
            if "/Sig" in args:
                res.stdout = "obj 5 0\n  << /Type /Sig >>\n"
            else:
                res.stdout = ""
            return res
        return original_run(args, **kwargs)

    with patch("canary_scan.lib.runners.subprocess.run", side_effect=mock_run):
        findings = c_pdf(rec, logger)

    sigs = [f for f in findings if f.subcategory == "pdf_signature"]
    assert len(sigs) == 1
    assert sigs[0].severity == "info"


def test_ooxml_printer_metadata(tmp_path):
    docx_path = tmp_path / "test_meta.docx"
    with zipfile.ZipFile(docx_path, "w") as z:
        core_content = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/">\n'
            "  <dc:creator>Alice Smith</dc:creator>\n"
            "  <cp:lastModifiedBy>Bob Jones</cp:lastModifiedBy>\n"
            "  <cp:lastPrinted>2026-06-25T12:00:00Z</cp:lastPrinted>\n"
            "</cp:coreProperties>"
        )
        z.writestr("docProps/core.xml", core_content)
        z.writestr("word/printerSettings/printerSettings1.bin", "dummy printer bytes")

    rec = make_rec(docx_path, Bucket.OOXML)
    logger = RunLogger(tmp_path / "test.log")
    findings = c_ooxml(rec, logger)

    creators = [f for f in findings if f.subcategory == "ooxml_creator"]
    modifiers = [f for f in findings if f.subcategory == "ooxml_last_modifier"]
    printeds = [f for f in findings if f.subcategory == "ooxml_last_printed"]
    printers = [f for f in findings if f.subcategory == "ooxml_printer_settings"]

    assert len(creators) == 1 and creators[0].evidence == "Alice Smith"
    assert len(modifiers) == 1 and modifiers[0].evidence == "Bob Jones"
    assert len(printeds) == 1 and printeds[0].evidence == "2026-06-25T12:00:00Z"
    assert len(printers) == 1


def test_email_header_analysis(tmp_path):
    eml_path = tmp_path / "test.eml"
    eml_content = (
        "Subject: Test Email\n"
        "X-Mailer: SuperMailer/1.0 (http://tracker.com/mailer)\n"
        "Received: from bad-server (http://tracker.com/routing)\n"
        "Content-Type: text/plain\n\n"
        "Body content"
    )
    eml_path.write_text(eml_content, encoding="utf-8")

    rec = make_rec(eml_path, Bucket.EMAIL)
    logger = RunLogger(tmp_path / "test.log")
    findings = c_email(rec, logger)

    mailer_hdrs = [f for f in findings if f.subcategory == "email_header/x_mailer"]
    recv_hdrs = [f for f in findings if f.subcategory == "email_header/received"]

    assert len(mailer_hdrs) == 1 and "tracker.com/mailer" in mailer_hdrs[0].evidence
    assert len(recv_hdrs) == 1 and "tracker.com/routing" in recv_hdrs[0].evidence


def test_canonicalization_fingerprint(tmp_path):
    f1 = tmp_path / "file1.txt"
    f2 = tmp_path / "file2.txt"

    # Write identical text but with line ending and spacing anomalies
    f1.write_bytes(b"Hello World\r\nLine 2 \r\n")
    f2.write_bytes(b"\xef\xbb\xbfHello World\nLine 2\n")  # With BOM and normalized newlines/no trailing spaces

    rec1 = make_rec(f1, Bucket.OTHER)
    rec2 = make_rec(f2, Bucket.OTHER)

    diffs = _diff_text([rec1, rec2])

    canon_diffs = [d for d in diffs if d.field == "canonicalization_diff"]
    assert len(canon_diffs) == 1
    assert "whitespace" in canon_diffs[0].description


def test_macro_fingerprint(tmp_path):
    ole_path = tmp_path / "test.doc"
    ole_path.write_bytes(b"dummy ole macro doc")

    rec = make_rec(ole_path, Bucket.OLE)
    logger = RunLogger(tmp_path / "test.log")

    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = (
        "olevba 0.60.1\n"
        "VBA code:\n"
        "Sub AutoOpen()\n"
        "  Dim user As String\n"
        '  user = Environ("UserName")\n'
        "  Dim host As String\n"
        "  host = WScript.Network.ComputerName\n"
        "End Sub\n"
    )
    mock_res.stderr = ""

    with patch("canary_scan.lib.runners.subprocess.run", return_value=mock_res):
        findings = c_ole(rec, logger)

    fingerprints = [f for f in findings if f.subcategory == "macro_fingerprint"]
    assert len(fingerprints) == 1
    assert "Environ" in fingerprints[0].finding
    assert "WScript.Network" in fingerprints[0].finding


def test_qr_code_url_detection(tmp_path):
    img_path = tmp_path / "image.png"
    from PIL import Image

    img = Image.new("RGB", (10, 10), color="white")
    img.save(img_path)

    rec = make_rec(img_path, Bucket.IMAGE)
    logger = RunLogger(tmp_path / "test.log")

    # Mock pyzbar.decode to return a mock QR code containing a URL callback
    mock_qr = MagicMock()
    mock_qr.data = b"Scan me! http://callback-tracker.com/target"

    import sys

    mock_pyzbar = MagicMock()
    mock_pyzbar_decode = MagicMock(return_value=[mock_qr])
    mock_pyzbar.decode = mock_pyzbar_decode
    mock_pyzbar.pyzbar = mock_pyzbar

    with patch.dict(sys.modules, {"pyzbar": mock_pyzbar, "pyzbar.pyzbar": mock_pyzbar}):
        findings = scan_image(rec, logger, None)

    qr_urls = [f for f in findings if f.subcategory == "qr_code_url"]
    assert len(qr_urls) == 1
    assert qr_urls[0].evidence == "http://callback-tracker.com/target"
