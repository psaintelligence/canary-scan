# Supported File Types

`canary-scan` classifies files into buckets at the inventory stage and routes each file to the appropriate set of canary checks. The table below shows what is inspected for each file type.

## Detection Matrix

| Bucket | Extensions | Canary vectors checked |
|---|---|---|
| **PDF** | `.pdf` | `/URI`, `/Launch`, `/GoToR`, `/OpenAction`, `/AA`, `/JS`, `/JavaScript`, `/EmbeddedFile`, `/XFA`, `/AcroForm` (form fields), `/OCProperties` (watermarks), `/Sig` (signatures), `/Encrypt`, incremental updates, visual page diffing via `mutool` |
| **RTF** | `.rtf` | `\objdata`, `\objhtml`, `\objupdate`, OLE objects, hyperlinks |
| **OOXML** | `.docx` `.xlsx` `.pptx` `.docm` `.xlsm` `.pptm` `.vsdx` | External rels, oleObjects, activeX controls, VBA macros, customXml, metadata GUIDs, DDE/DDEAUTO, header/footer external links, content type injection, zip encryption check |
| **ODF** | `.odt` `.ods` `.odp` `.odg` `.odf` | External refs in `content.xml` / `styles.xml` / `meta.xml`, macro detection |
| **OLE** | `.doc` `.xls` `.ppt` `.msg` `.pub` `.hwp` | OLE streams, VBA macros, hyperlinks, `.msg` HTML body beacons, hyperlink streams, environment variable fingerprinting |
| **HTML** | `.html` `.htm` `.mht` `.mhtml` | Tracking pixels, `<script>`, `<iframe>`, CSS `url()`, `ping=` attributes, MHTML boundary `Content-Location` parsing |
| **Email** | `.eml` | Tracking pixels, read receipts, external image loads, routing header analysis |
| **Image** | `.jpg` `.jpeg` `.png` `.gif` `.bmp` `.tif` `.tiff` `.webp` `.svg` | EXIF/GPS/serial numbers, PNG structure and trailing chunks (`pngcheck`), SVG scripts and `href`, steganography via `steghide`/`stegseek`, EXIF thumbnail visual mismatch, QR code remote URL detection |
| **CSV** | `.csv` `.tsv` | Formula injection: `=HYPERLINK`, `=WEBSERVICE`, `=IMPORTDATA`, `=IMPORTXML`, `=IMAGE` |
| **XML** | `.xml` `.xsd` `.xsl` | XXE entity references, XSLT `document()` calls, external DTD references |
| **Archive** | `.zip` `.tar` `.tar.gz` `.tgz` `.7z` `.rar` `.iso` `.cab` `.epub` `.chm` `.lnk` | Recursive member scanning (depth-limited), zip-slip path validation, Windows LNK shortcut target parsing |
| **Specialised** | audio, video, fonts, DICOM, iWork, OneNote | Metadata fingerprints, unique device/hardware IDs (opt-in via `--enable-specialized`) |

---

## Specialised file types

Specialised types require additional Python packages and must be explicitly enabled with `--enable-specialized`:

| File type | Python package | What is checked |
|---|---|---|
| Fonts (`.ttf`, `.otf`, `.woff`) | `fonttools` | Font name table entries, unique IDs, embedded metadata |
| DICOM (`.dcm`) | `pydicom` | Patient/device/institution metadata, UID fingerprinting |
| Audio (`.mp3`, `.flac`, `.ogg`) | `mutagen` | ID3 tags, APIC embedded images, unique identifiers |
| Video (`.mp4`, `.mkv`, `.mov`) | `ffprobe` | Container metadata, encoder fingerprints |
| OneNote (`.one`) | `pyOneNote` | Embedded objects, metadata |

Install specialised deps:

```bash
pip install "canary-scan[specialized]"
```

---

## Adding new file types

`canary-scan` uses a stage registry pattern. New file type handlers can be registered without modifying core code. See the `StageRegistry` in `canary_scan/lib/orchestrator.py` and the existing scanner modules under `canary_scan/scanners/` for reference implementations.

---

## Bundled third-party tools

`canary-scan` includes working reimplementations of Didier Stevens' tools for air-gap-friendly operation:

| Tool | Purpose | License |
|---|---|---|
| `pdfid` | Scan PDF files for active elements and risky keywords | BSD 2-Clause |
| `pdf-parser` | Extract objects and analyse PDF structure | BSD 2-Clause |
| `rtfdump` | Analyse and dump elements of RTF files | BSD 2-Clause |

If the original tools are present on `PATH`, they are preferred automatically. Otherwise the bundled versions run transparently. Provenance and version pins are recorded in `src/canary_scan/bundled/VERSIONS.txt`.
