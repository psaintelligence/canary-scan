from __future__ import annotations

from enum import Enum

from canary_scan import __version__ as TOOL_VERSION  # noqa: F401

TOOL_NAME = "canary-scan"
DEFAULT_OUTDIR = ".canary-scan"
DEFAULT_MIN_CLUSTER_SIZE = 2
DEFAULT_MAX_ARCHIVE_DEPTH = 3
DEFAULT_WORKERS = 8
SCHEMA_VERSION = "1.0"
LOCK_FILE = "canary-scan.lock"
LOG_FILE = "canary-scan.log"
STATE_FILE = "canary-scan-state.json"

STAGE_NAMES = ["inventory", "metadata", "remote-refs", "embedded", "stego", "uniqueness", "report"]
STAGE_ARTEFACTS = {
    "inventory": "canary-scan-inventory.json",
    "metadata": "canary-scan-metadata.json",
    "remote-refs": "canary-scan-remote-refs.json",
    "embedded": "canary-scan-embedded.json",
    "stego": "canary-scan-stego.json",
    "uniqueness": "canary-scan-unique-clusters.json",
    "report": "canary-scan-report.json",
}
STAGE_SHORT_NAMES = {
    "inventory": "Inventory",
    "metadata": "Metadata",
    "remote-refs": "Remote References",
    "embedded": "Embedded Objects",
    "stego": "Steganography",
    "uniqueness": "Uniqueness & Fingerprints",
    "report": "Final Report",
}
STAGE_DESCRIPTIONS = {
    "inventory": "Inventory (walks filesystem, hashes, identifies MIME types, and classifies files)",
    "metadata": "Metadata (extracts metadata via exiftool, scans for URLs/PII)",
    "remote-refs": "Remote References (scans for XXE, tracking links, external relations)",
    "embedded": "Embedded Objects (extracts nested binaries, raster images, OLE/ActiveX)",
    "stego": "Steganography (scans images for steganographic carriers & cracked passphrases)",
    "uniqueness": "Uniqueness & Fingerprints (clusters near-duplicates to find per-recipient canaries)",
    "report": "Final Report (merges stage outputs, filters by severity, formats final report)",
}
STAGE_TMP_DIR = "canary-scan-tmp"
EMBEDDED_DIR = "canary-scan-embedded"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


class Bucket(str, Enum):
    PDF = "pdf"
    RTF = "rtf"
    OOXML = "ooxml"
    ODF = "odf"
    OLE = "ole"
    HTML = "html"
    EMAIL = "email"
    IMAGE = "image"
    CSV = "csv"
    XML = "xml"
    ARCHIVE = "archive"
    OTHER = "other"
    SPECIALIZED = "specialized"


EXTENSION_BUCKETS: dict[str, Bucket] = {}
for _ext in ("pdf",):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.PDF
for _ext in ("rtf",):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.RTF
for _ext in ("docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "vsdx"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.OOXML
for _ext in ("odt", "ods", "odp", "odg", "odf"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.ODF
for _ext in ("doc", "xls", "ppt", "msg", "pub", "hwp"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.OLE
for _ext in ("html", "htm", "mht", "mhtml"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.HTML
for _ext in ("eml",):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.EMAIL
for _ext in ("jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "svg"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.IMAGE
for _ext in ("csv", "tsv"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.CSV
for _ext in ("xml", "xsd", "xsl"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.XML
for _ext in ("zip", "tar", "tgz", "7z", "rar", "iso", "cab", "epub", "chm"):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.ARCHIVE
for _ext in ("gz",):
    EXTENSION_BUCKETS[f".{_ext}"] = Bucket.ARCHIVE

SPECIALIZED_EXTENSIONS = {
    ".mp3",
    ".m4a",
    ".flac",
    ".wav",
    ".aac",
    ".mp4",
    ".mov",
    ".mkv",
    ".avi",
    ".webm",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".dcm",
    ".pages",
    ".numbers",
    ".key",
    ".one",
}

SPECIALIZED_BUCKETS = {
    ".mp3": "audio",
    ".m4a": "audio",
    ".flac": "audio",
    ".wav": "audio",
    ".aac": "audio",
    ".mp4": "video",
    ".mov": "video",
    ".mkv": "video",
    ".avi": "video",
    ".webm": "video",
    ".ttf": "font",
    ".otf": "font",
    ".woff": "font",
    ".woff2": "font",
    ".dcm": "dicom",
    ".pages": "iwork",
    ".numbers": "iwork",
    ".key": "iwork",
    ".one": "onenote",
}


CATEGORY_INFO = {
    "active_url": "Remote URL referenced that could phone home on open",
    "javascript": "Embedded JavaScript that could execute on open",
    "open_action": "PDF OpenAction or auto-trigger that executes on open",
    "embedded_object": "Embedded OLE/activeX object that could execute",
    "metadata_unique": "Metadata field containing a likely per-recipient unique value",
    "metadata_pii": "Metadata field containing PII (author, GPS, serial)",
    "hidden_text": "Hidden text layer or optional-content layer in document",
    "steg_carrier": "File is a steganography carrier (payload may be present)",
    "steg_payload": "Steganographic payload extracted (password cracked)",
    "unique_fingerprint": "Near-duplicate files differ by a fingerprint value",
    "mtime_anomaly": "Modification time is anomalous relative to peers",
    "suspicious_metadata_field": "Non-standard or unusual metadata field",
    "formula_injection": "CSV/spreadsheet formula that could execute on open",
    "external_entity": "XML external entity or XSLT external reference (XXE)",
    "tracking_pixel": "Email/HTML tracking pixel or web beacon",
    "read_receipt": "Email read-receipt request header",
    "hyperlink": "External hyperlink in document body",
    "archive_nested": "Archive contains nested archive requiring recursion",
    "no_bucket_check": "No bucket-specific canary check defined for this file type",
    "inventory": "File identified and inventoried during initial scan",
    "form_field": "PDF contains interactive form fields",
    "watermark": "PDF contains optional content groups / watermark layers",
    "incremental_update": "PDF contains incremental update (potential hidden content or history)",
    "encrypted_file": "File is encrypted or password-protected",
}


CANARY_CATEGORIES = set(CATEGORY_INFO.keys())


DEPS: dict[str, tuple[str, str, str, str]] = {
    "exiftool": ("required", "[apt|rpm|apk] libimage-exiftool-perl", "exiftool", "Metadata extraction and analysis"),
    "qpdf": ("required", "[apt|rpm|apk] qpdf", "qpdf", "PDF structure analysis and linearization checks"),
    "pdftotext": ("required", "[apt|rpm|apk] poppler-utils", "pdftotext", "Extract text content from PDF"),
    "pdfimages": ("required", "[apt|rpm|apk] poppler-utils", "pdfimages", "Extract raster images from PDF"),
    "pdftohtml": ("required", "[apt|rpm|apk] poppler-utils", "pdftohtml", "Convert PDF pages to HTML"),
    "mutool": ("required", "[apt|rpm|apk] mupdf-tools", "mutool", "PDF and XPS document rendering and inspection"),
    "olevba": ("required", "[pip] oletools", "olevba", "VBA macro code extraction"),
    "oleobj": ("required", "[pip] oletools", "oleobj", "Embedded OLE object extraction"),
    "rtfobj": ("required", "[pip] oletools", "rtfobj", "Embedded RTF object extraction"),
    "rg": ("required", "[apt|rpm|apk] ripgrep", "rg", "Fast regex-based text search"),
    "unzip": ("required", "[apt|rpm|apk] unzip", "unzip", "Unpack ZIP-compressed archives"),
    "7z": ("required", "[apt|rpm|apk] p7zip-full", "7z", "Unpack 7z and other archive formats"),
    "unrar": ("optional", "[apt|rpm|apk] unrar", "unrar", "Unpack RAR-compressed archives"),
    "compare": ("optional", "[apt|rpm|apk] imagemagick", "compare", "Image pixel comparison and diffing"),
    "steghide": ("optional", "[apt|rpm] steghide", "steghide", "Steganographic analysis for JPEG/BMP images"),
    "stegseek": ("optional", "[apt] stegseek", "stegseek", "Fast brute-force steganography passphrase cracker"),
    "peepdf": ("optional", "[pip] peepdf", "peepdf", "Deep interactive PDF file analysis"),
    "pngcheck": ("optional", "[apt|rpm] pngcheck", "pngcheck", "PNG file structure validation and integrity check"),
    "jq": ("optional", "[apt|rpm|apk] jq", "jq", "JSON command line processor"),
    "extract_msg": ("optional", "[pip] extract_msg", "extract_msg", "Parse Outlook .msg email files"),
    "python-liblnk": ("optional", "[pip] python-liblnk", "python-liblnk", "Parse Windows shortcut (.lnk) files"),
    "pdfid": ("bundled", "[bundled] pdfid.py", "pdfid.py", "Scan PDF files for active elements and keywords"),
    "pdf-parser": (
        "bundled",
        "[bundled] pdf_parser.py",
        "pdf_parser.py",
        "Extract objects and analyze PDF file structure",
    ),
    "rtfdump": ("bundled", "[bundled] rtfdump.py", "rtfdump.py", "Analyze and dump elements of RTF files"),
}

SPECIALIZED_DEPS: dict[str, tuple[str, str, str, str]] = {
    "fonttools": ("optional", "[apt|rpm|apk] python3-fonttools", "fonttools", "Font name table fingerprinting"),
    "pydicom": ("optional", "[apt|rpm|apk] python3-pydicom", "pydicom", "DICOM medical image metadata analysis"),
    "mutagen": ("optional", "[apt|rpm|apk] python3-mutagen", "mutagen", "Audio metadata analysis"),
    "ffprobe": ("optional", "[apt|rpm|apk] ffmpeg", "ffprobe", "Video file metadata analysis"),
    "pyOneNote": ("optional", "[pip] pyOneNote", "pyOneNote", "OneNote file format parsing"),
}

PACKAGE_MAPPINGS = {
    "libimage-exiftool-perl": {
        "apt": "libimage-exiftool-perl",
        "rpm": "perl-Image-ExifTool",
        "apk": "perl-image-exiftool",
    },
    "qpdf": {"apt": "qpdf", "rpm": "qpdf", "apk": "qpdf"},
    "poppler-utils": {"apt": "poppler-utils", "rpm": "poppler-utils", "apk": "poppler-utils"},
    "mupdf-tools": {"apt": "mupdf-tools", "rpm": "mupdf", "apk": "mupdf"},
    "ripgrep": {"apt": "ripgrep", "rpm": "ripgrep", "apk": "ripgrep"},
    "unzip": {"apt": "unzip", "rpm": "unzip", "apk": "unzip"},
    "p7zip-full": {"apt": "p7zip-full", "rpm": "7zip", "apk": "7zip"},
    "unrar": {"apt": "unrar", "rpm": "unrar", "apk": "[build] build from source"},
    "imagemagick": {"apt": "imagemagick", "rpm": "ImageMagick", "apk": "imagemagick"},
    "steghide": {"apt": "steghide", "rpm": "steghide", "apk": "[build] build from source"},
    "stegseek": {"apt": "stegseek", "rpm": "[github] github release", "apk": "[github] github release"},
    "pngcheck": {"apt": "pngcheck", "rpm": "pngcheck", "apk": "[build] build from source"},
    "jq": {"apt": "jq", "rpm": "jq", "apk": "jq"},
    "python3-fonttools": {"apt": "python3-fonttools", "rpm": "python3-fonttools", "apk": "py3-fonttools"},
    "python3-pydicom": {"apt": "python3-pydicom", "rpm": "python3-pydicom", "apk": "py3-pydicom"},
    "python3-mutagen": {"apt": "python3-mutagen", "rpm": "python3-mutagen", "apk": "py3-mutagen"},
    "ffmpeg": {"apt": "ffmpeg", "rpm": "ffmpeg-free", "apk": "ffmpeg"},
}


SARIF_LEVEL_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class FormatOption(str, Enum):
    json = "json"
    csv = "csv"
    sarif = "sarif"
    all = "all"


class SeverityThreshold(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class StageName(str, Enum):
    inventory = "inventory"
    metadata = "metadata"
    remote_refs = "remote-refs"
    embedded = "embedded"
    stego = "stego"
    uniqueness = "uniqueness"
    report = "report"
