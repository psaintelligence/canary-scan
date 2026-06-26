# Install

## Docker (Recommended)

The recommended way to run `canary-scan` is via Docker, as the image comes pre-bundled with all necessary system utilities (like `exiftool`, `qpdf`, `poppler`, etc.) and optional dependencies.

### GitHub Container Registry

You can run the pre-built image directly from GitHub Container Registry:

```bash
docker run --rm \
  -v /path/to/datasource:/data:ro \
  -v /path/to/output:/output \
  ghcr.io/psaintelligence/canary-scan:latest scan /data -o /output
```

### Local Build

To build and run the Docker container locally:

```bash
# Build the image
docker build -t canary-scan .

# Run the scan
docker run --rm \
  -v /path/to/datasource:/data:ro \
  -v /path/to/output:/output \
  canary-scan scan /data -o /output
```

---

## Python package (Alternative)

Install via `pipx` (keeps canary-scan isolated from your system Python):

```bash
pipx install canary-scan
```

Or with `pip`:

```bash
pip install canary-scan
```

To enable optional imaging features (QR code detection, EXIF thumbnail mismatch):

```bash
pip install "canary-scan[imaging]"
```

To enable specialised file type scanning (fonts, DICOM, audio):

```bash
pip install "canary-scan[specialized]"
```

---

## System dependencies

### Required

| Binary | Ubuntu 24.04 package | Used by |
|---|---|---|
| `exiftool` | `libimage-exiftool-perl` | metadata, remote-refs, stego, uniqueness |
| `qpdf` | `qpdf` | remote-refs, uniqueness |
| `pdftotext` | `poppler-utils` | embedded, stego, uniqueness |
| `pdfimages` | `poppler-utils` | embedded |
| `pdftohtml` | `poppler-utils` | stego |
| `mutool` | `mupdf-tools` | stego |
| `olevba` | `oletools` (Python dep) | remote-refs, embedded |
| `oleobj` | `oletools` (Python dep) | remote-refs, embedded |
| `rtfobj` | `oletools` (Python dep) | remote-refs, embedded |
| `rg` | `ripgrep` | remote-refs |
| `unzip` | `unzip` | remote-refs, embedded |
| `7z` | `p7zip-full` | remote-refs (archive extraction) |

Install on Ubuntu 24.04:

```bash
sudo apt install libimage-exiftool-perl qpdf poppler-utils mupdf-tools \
    ripgrep unzip p7zip-full
```

### Optional

| Binary | Package | Used by | Notes |
|---|---|---|---|
| `unrar` | `unrar` | remote-refs | RAR archive extraction |
| `compare` | `imagemagick` | uniqueness | Image pixel diff |
| `steghide` | `steghide` | stego | JPEG/BMP steganography detection |
| `stegseek` | [GitHub release](https://github.com/RickdeJager/stegseek/releases) | stego | Brute-force steganography cracker (opt-in) |
| `peepdf` | `pip install peepdf-3` | remote-refs | Deep PDF stream analysis |
| `pngcheck` | `pngcheck` | stego | PNG chunk structure audit |
| `jq` | `jq` | User-facing | Pretty-print JSON output |

Install all optional tools:

```bash
sudo apt install unrar imagemagick steghide pngcheck jq
```

### Specialised (opt-in via `--enable-specialized`)

| Package | Purpose |
|---|---|
| `fonttools` | Font name table fingerprinting |
| `pydicom` | DICOM medical imaging metadata |
| `mutagen` | Audio ID3/APIC metadata |
| `ffprobe` | Video metadata |
| `pyOneNote` | OneNote file parsing |

Install:

```bash
pip install "canary-scan[specialized]"
```

### Check your installation

```bash
# Show dependency status table
canary-scan deps

# Show install commands for anything missing
canary-scan deps --fix-hints

# Include specialised deps in the check
canary-scan deps --enable-specialized
```

---

## Air-gap install

For analysis environments with no internet access, pre-download everything on a networked host and transfer via USB.

### 1. On a networked host

```bash
# Download the Python wheel and all transitive dependencies
pipx install canary-scan
pipx runpip canary-scan freeze > requirements.txt
python3 -m pip download canary-scan -r requirements.txt -d ./wheelhouse/

# Download .deb packages for system tools
apt-get download libimage-exiftool-perl qpdf poppler-utils mupdf-tools \
    ripgrep unzip p7zip-full unrar
```

### 2. Transfer to the air-gapped host

Copy `wheelhouse/`, the `.deb` files, and the `canary-scan` source to the analysis host via USB.

### 3. On the air-gapped host

```bash
# Install system deps from local .deb files
sudo dpkg -i *.deb

# Install canary-scan from the local wheelhouse
pipx install --pip-args="--no-index --find-links ./wheelhouse" canary-scan
```

!!! note "Bundled tools"
    `canary-scan` bundles working reimplementations of Didier Stevens' `pdfid`, `pdf-parser`, and `rtfdump` scripts for air-gap-friendly operation. If the originals are on your `PATH`, they are preferred automatically. Otherwise the bundled versions run transparently. See `src/canary_scan/bundled/README.md` for provenance and licensing.
