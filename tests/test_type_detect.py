"""Test file-type detection."""

from canary_scan.lib.config import Bucket
from canary_scan.lib.type_detect import detect_bucket, extension_of


def test_pdf_detection():
    assert detect_bucket("file.pdf", "PDF document") == Bucket.PDF
    assert detect_bucket("file.PDF", "") == Bucket.PDF


def test_rtf_detection():
    assert detect_bucket("file.rtf", "Rich Text Format") == Bucket.RTF


def test_ooxml_detection():
    assert detect_bucket("file.docx", "") == Bucket.OOXML
    assert detect_bucket("file.xlsx", "") == Bucket.OOXML
    assert detect_bucket("file.pptx", "") == Bucket.OOXML
    assert detect_bucket("file.vsdx", "") == Bucket.OOXML


def test_odf_detection():
    assert detect_bucket("file.odt", "") == Bucket.ODF
    assert detect_bucket("file.ods", "") == Bucket.ODF


def test_ole_detection():
    assert detect_bucket("file.doc", "Composite Document File") == Bucket.OLE
    assert detect_bucket("file.msg", "") == Bucket.OLE


def test_html_detection():
    assert detect_bucket("file.html", "HTML document") == Bucket.HTML
    assert detect_bucket("file.htm", "") == Bucket.HTML
    assert detect_bucket("file.mhtml", "") == Bucket.HTML


def test_email_detection():
    assert detect_bucket("file.eml", "") == Bucket.EMAIL


def test_image_detection():
    assert detect_bucket("file.jpg", "JPEG image") == Bucket.IMAGE
    assert detect_bucket("file.png", "") == Bucket.IMAGE
    assert detect_bucket("file.svg", "") == Bucket.IMAGE
    assert detect_bucket("file.gif", "") == Bucket.IMAGE


def test_csv_detection():
    assert detect_bucket("file.csv", "") == Bucket.CSV
    assert detect_bucket("file.tsv", "") == Bucket.CSV


def test_xml_detection():
    assert detect_bucket("file.xml", "XML document") == Bucket.XML


def test_archive_detection():
    assert detect_bucket("file.zip", "Zip archive") == Bucket.ARCHIVE
    assert detect_bucket("file.tar.gz", "") == Bucket.ARCHIVE
    assert detect_bucket("file.7z", "") == Bucket.ARCHIVE
    assert detect_bucket("file.epub", "") == Bucket.ARCHIVE


def test_other_detection():
    assert detect_bucket("file.xyz", "some unknown type") == Bucket.OTHER


def test_specialized_opt_in():
    assert detect_bucket("file.mp3", "") == Bucket.OTHER
    assert detect_bucket("file.mp3", "", enable_specialized=True) == Bucket.SPECIALIZED


def test_extension():
    assert extension_of("file.PDF") == ".pdf"
    assert extension_of("/path/to/file.tar.gz") == ".gz"
