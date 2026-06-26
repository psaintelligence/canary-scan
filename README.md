# canary-scan

[![python](https://img.shields.io/pypi/pyversions/canary-scan.svg)](https://github.com/psaintelligence/canary-scan/)
[![license](https://img.shields.io/github/license/psaintelligence/canary-scan.svg)](https://github.com/psaintelligence/canary-scan)

**Scan document data-sources for canaries, trackers, web beacons, and per-recipient fingerprints before interacting with supplied datasets.**

When you receive a large document dump from an external party — a leak, legal disclosure, or investigation — those files and documents can contain deliberate or indirect canaries: tracking pixels, embedded JavaScript, remote template links, steganographic watermarks, or per-recipient metadata fingerprints that phone home the moment a file is opened.

`canary-scan` inspects files **without opening it in its native viewer**, extracting and analysing raw structure, metadata, embedded objects, and near-duplicate fingerprints to surface anything that may reveal to an external party that the data-source is being examined.

→ **Full documentation:** [psaintelligence.github.io/canary-scan](https://psaintelligence.github.io/canary-scan)

---

## Quick Start (Docker)

The recommended way to run `canary-scan` is via Docker, as the image bundles all required system utilities and dependencies:

```bash
# Run the scan using the GitHub Container Registry image
docker run --rm \
  -v /mnt/datasource:/data:ro \
  -v $(pwd)/canary-scan-out:/output \
  ghcr.io/psaintelligence/canary-scan:latest scan /data -o /output

# Review findings
jq '.[] | select(.severity=="critical")' canary-scan-out/canary-scan-report.json
```

---

## Quick Start (pipx)

If you prefer to run `canary-scan` directly on your host machine:

```bash
# 1. Install canary-scan
pipx install canary-scan

# 2. Install required system dependencies (Ubuntu 24.04 example)
sudo apt install libimage-exiftool-perl qpdf poppler-utils mupdf-tools \
    ripgrep unzip p7zip-full

# 3. Run the scan
canary-scan scan /mnt/datasource
```

---

## Detection pipeline

Seven sequential stages: **inventory → metadata → remote-refs → embedded → stego → uniqueness → report**

Each stage writes a JSONL artefact to `.canary-scan/`. Run `canary-scan --guide` for a concise cheat sheet.

---

## License

Apache-2.0. Bundled third-party scripts (`pdfid`, `pdf-parser`, `rtfdump`) are BSD 2-Clause — see `src/canary_scan/bundled/README.md`.
