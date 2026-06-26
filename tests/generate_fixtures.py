"""Generate synthetic canary test fixtures.

Usage:
    python3 tests/generate_fixtures.py [output_dir]
"""

import io
import struct
import sys
import zipfile
from pathlib import Path


def generate_pdf_with_uri(filepath: Path):
    """Minimal PDF with /URI action."""
    pdf = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
4 0 obj << /Type /Action /S /URI /URI (https://tracker.example.com/pixel.gif?d=canary) >> endobj
xref
0 5
0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000194 00000 n \n
trailer << /Size 5 /Root 1 0 R >>
startxref
290
%%EOF"""
    filepath.write_bytes(pdf)


def generate_pdf_with_js(filepath: Path):
    """Minimal PDF with JavaScript."""
    pdf = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction << /Type /Action /S /JavaScript /JS (app.launchURL("https://evil.example.com/canary");) >> >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
xref
0 4
0000000000 65535 f \n0000000009 00000 n \n0000000150 00000 n \n0000000207 00000 n \n
trailer << /Size 4 /Root 1 0 R >>
startxref
282
%%EOF"""
    filepath.write_bytes(pdf)


def generate_rtf_with_objdata(filepath: Path):
    """RTF with objdata (OLE object placeholder)."""
    rtf = r"""{\rtf1\ansi\ansicpg1252\deff0
{\object\objemb{\*\objdata 01050000 00000000 04000000 00000000}}
{\field{\*\fldinst HYPERLINK "https://tracker.example.com/canary"}{\fldrslt Click here}}}
"""
    filepath.write_text(rtf, encoding="utf-8")


def generate_docx_with_external_link(filepath: Path):
    """DOCX (zip) with external relationship."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(
            "[Content_Types].xml",
            '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/></Types>',
        )
        z.writestr(
            "_rels/.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>',
        )
        z.writestr(
            "word/document.xml",
            '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:hyperlink r:id="rId1" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:r><w:t>Link</w:t></w:r></w:hyperlink></w:p></w:body></w:document>',
        )
        z.writestr(
            "word/_rels/document.xml.rels",
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="https://tracker.example.com/docx-canary" TargetMode="External"/></Relationships>',
        )
    filepath.write_bytes(buf.getvalue())


def generate_csv_formula_injection(filepath: Path):
    """CSV with formula injection."""
    filepath.write_text(
        'name,value\n=HYPERLINK("https://evil.example.com/canary","click"),1\nnormal,2\n', encoding="utf-8"
    )


def generate_xml_xxe(filepath: Path):
    """XML with XXE."""
    xml = '<?xml version="1.0"?>\n<!DOCTYPE foo [\n  <!ENTITY xxe SYSTEM "https://evil.example.com/xxe-canary">\n]>\n<root>&xxe;</root>\n'
    filepath.write_text(xml, encoding="utf-8")


def generate_html_beacon(filepath: Path):
    """HTML with tracking pixel and external script."""
    html = '<html><body><img src="https://tracker.example.com/pixel.gif" width="1" height="1"><script src="https://evil.example.com/track.js"></script></body></html>\n'
    filepath.write_text(html, encoding="utf-8")


def generate_eml_tracking_pixel(filepath: Path):
    """EML with tracking pixel and read receipt."""
    eml = """From: sender@example.com
To: recipient@example.com
Subject: Test
Disposition-Notification-To: sender@example.com
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body><img src="https://tracker.example.com/pixel.gif" width="1" height="1">Hello</body></html>
"""
    filepath.write_text(eml, encoding="utf-8")


def generate_png_with_text(filepath: Path):
    """Minimal PNG with tEXt chunk containing a URL."""
    sig = b"\x89PNG\r\n\x1a\n"
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data
    import zlib

    ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_data) & 0xFFFFFFFF)
    text_data = b"Comment\x00https://tracker.example.com/png-canary"
    text_chunk = (
        struct.pack(">I", len(text_data))
        + b"tEXt"
        + text_data
        + struct.pack(">I", zlib.crc32(b"tEXt" + text_data) & 0xFFFFFFFF)
    )
    raw = b"\x00\x00"
    idat_data = zlib.compress(raw)
    idat = (
        struct.pack(">I", len(idat_data))
        + b"IDAT"
        + idat_data
        + struct.pack(">I", zlib.crc32(b"IDAT" + idat_data) & 0xFFFFFFFF)
    )
    iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF)
    filepath.write_bytes(sig + ihdr + text_chunk + idat + iend)


def generate_near_dup_pdfs(outdir: Path):
    """Two PDFs differing by one whitespace char."""
    base = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
xref
0 4
0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n
trailer << /Size 4 /Root 1 0 R >>
startxref
190
%%EOF"""
    (outdir / "near_dup_a.pdf").write_bytes(base)
    modified = base.replace(b"%%EOF", b" %%EOF")
    (outdir / "near_dup_b.pdf").write_bytes(modified)


def generate_zip_with_pdf(filepath: Path):
    """ZIP containing a PDF with URI canary."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        pdf = b"""%PDF-1.4
1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >> endobj
2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj
3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >> endobj
4 0 obj << /Type /Action /S /URI /URI (https://tracker.example.com/nested-canary) >> endobj
trailer << /Size 5 /Root 1 0 R >>
%%EOF"""
        z.writestr("inner.pdf", pdf)
    filepath.write_bytes(buf.getvalue())


def generate_all(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    generate_pdf_with_uri(outdir / "pdf_uri_canary.pdf")
    generate_pdf_with_js(outdir / "pdf_js_canary.pdf")
    generate_rtf_with_objdata(outdir / "rtf_objdata_canary.rtf")
    generate_docx_with_external_link(outdir / "docx_external_link.docx")
    generate_csv_formula_injection(outdir / "csv_formula_injection.csv")
    generate_xml_xxe(outdir / "xml_xxe.xml")
    generate_html_beacon(outdir / "html_beacon.html")
    generate_eml_tracking_pixel(outdir / "eml_tracking_pixel.eml")
    generate_png_with_text(outdir / "png_text_canary.png")
    generate_near_dup_pdfs(outdir)
    generate_zip_with_pdf(outdir / "nested.zip")
    print(f"Generated fixtures in {outdir}")


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/fixtures")
    generate_all(out)
