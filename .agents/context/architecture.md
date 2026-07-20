# architecture.md

Guidance for AI coding agents working in the `canary-scan` repository.

---

## Documentation Hierarchy

1. **`.agent/README.md`** — Agent index, active rules, skills, workflows, and project spec.
2. **`.agent/rules/*.md`** — Hard constraints (must always be obeyed).
3. **`.agent/context/*.md`** — Project context and architectural rationale (this file).
4. **`.agent/workflows/*.md`** — Step-by-step procedures for common tasks.
5. **`README.md`** (project root) — Human-readable overview and setup.

When documentation conflicts, rules > context > workflows > project README.

---

## Project Overview

`canary-scan` is a Python CLI tool that scans document dumps for canaries, trackers, web beacons, and per-recipient fingerprints **before** a practitioner opens any file in its native viewer. It is designed for investigation, legal disclosure, and leak-analysis workflows where the dump may contain deliberate or indirect mechanisms that alert an external party that the data is being observed.

The tool inspects files at the raw-byte / structural level — never opening them in Acrobat, Word, image viewers, or other trigger surfaces. It extracts metadata, embedded objects, remote references, steganographic carriers, and near-duplicate fingerprints across 12 file-type buckets.

---

## Core Architectural Principles

1. **No native viewers.** Files are never opened in their associated application. All text extraction via `pdftotext`, `strings`, stdlib parsers, or raw-byte tools.
2. **Read-only warning (advisory).** The tool strongly recommends the dump directory is on a read-only mount and emits a prominent warning via `findmnt` when it is not, but does not abort — practitioners who have snapshotted the data may proceed on a writable tree at their own risk. See ADR-004.
3. **Air-gap friendly.** All third-party scripts are bundled; no network access required at runtime. Installable via `pip download` wheelhouse procedure.
4. **Evidence-safe.** Default `--resume` skips completed stages; `runs[]` audit trail in state.json is append-only; flock prevents concurrent runs on the same outdir.
5. **Structured output.** Default format is JSON (JSONL stream) for piping into `jq` / SIEM / other tools. CSV and SARIF also available.
6. **Per-bucket routing.** remote-refs stage and uniqueness stage dispatch to file-type-specific detection logic.

---

## Technology Stack

- **Language:** Python 3.10+
- **CLI framework:** Typer (`typer[all]`) with Rich output
- **Dependency manager:** uv (with `exclude-newer = "14 days ago"` for supply-chain safety)
- **Build backend:** Hatchling
- **Linter/formatter:** Ruff
- **Test framework:** pytest
- **External binaries:** exiftool, qpdf, poppler-utils, mupdf-tools, oletools, ripgrep, p7zip
- **Bundled scripts:** Didier Stevens' `pdfid.py`, `pdf-parser.py`, `rtfdump.py` (BSD 2-Clause)

### Development Tooling

- `Makefile` — defines a `UV` prefix (`UV_PROJECT_ENVIRONMENT` / `UV_CACHE_DIR` / `UV_LINK_MODE`) used by every target, so `make` invocations enforce isolation without a wrapper script.
- `src/canary_scan/bundled/fetch.sh` — fetches and pins Didier Stevens scripts with provenance headers
- `Makefile` — `setup`, `vendor`, `sync`, `test`, `lint`, `format`, `run`, `clean` targets
- No local `.venv` — venv at `${HOME}/.local/venvs/canary-scan`

---

## Repository Structure

```
canary-scan/
├── .agents/                   # Agent configuration (rules, context, workflows, skills)
├── .github/workflows/         # CI (ci.yml) + PyPI publish (publish.yml)
├── src/
│   └── canary_scan/
│       ├── __init__.py
│       ├── main.py                # Typer CLI app entrypoint and registration
│       ├── commands/              # Individual subcommand modules
│       │   ├── deps.py            # 'deps' command handler
│       │   ├── scan.py            # 'scan' command handler & pipeline orchestrator
│       │   ├── stage.py           # 'stage' command handler
│       │   └── report.py          # 'report' command handler & report builder
│       ├── lib/
│       │   ├── config.py          # Dep registry, severity, buckets, CLI options
│       │   ├── deps.py            # Dependency checking
│       │   ├── guide.py           # --guide workflow text
│       │   ├── io.py              # JSONL/CSV/SARIF/stdout writers
│       │   ├── models.py          # Finding, FileRecord dataclasses
│       │   ├── runners.py         # safe_subprocess + log
│       │   ├── safety.py          # Read-only mount enforcement
│       │   ├── state.py           # state.json, runs[] audit, flock
│       │   └── type_detect.py     # file(1) output → bucket mapping
│       ├── scanners/              # Stage scanners
│       │   ├── inventory.py       # sha256, stat, file(1), bucket detection
│       │   ├── metadata.py        # exiftool -a -G -j extraction
│       │   ├── remote_refs.py     # Per-bucket tracking scanners
│       │   ├── embedded.py        # nested extraction
│       │   ├── stego.py           # stego checks
│       │   └── uniqueness.py      # near-duplicate clustering
│       └── bundled/
│           ├── VERSIONS.txt       # Provenance for Didier Stevens scripts
│           ├── fetch.sh           # Fetch + pin Didier Stevens scripts
│           ├── README.md          # Third-Party Licenses & details
│           ├── pdfid.py           # Pinned from Didier Stevens Beta
│           ├── pdf_parser.py      # Pinned from Didier Stevens Beta
│           └── rtfdump.py         # Pinned from Didier Stevens Beta
├── scripts/
│   └── dependency-package-resolver.py
├── tests/
│   ├── conftest.py
│   ├── generate_fixtures.py   # Synthetic canary files (PDF /URI, RTF objdata, DOCX, CSV, etc.)
│   ├── fixtures/              # Generated test canaries
│   └── test_*.py              # Per-stage + module tests
├── Makefile
├── pyproject.toml
├── README.md
└── LICENSE                    # Apache-2.0
```

---

## Data Flow & Feature Phasing

### Pipeline Stages

| Name | Input | Output | Description |
|---|---|---|---|
| inventory | dumpdir | `canary-scan-inventory.json` | Walk filesystem, sha256, stat, `file(1)` mime, bucket classification |
| metadata | inventory | `canary-scan-metadata.json` | `exiftool -a -G -j -r` per file; flag PII, unique IDs, URLs in metadata |
| remote-refs | inventory | `canary-scan-remote-refs.json` | Per-bucket: PDF keywords/URIs, RTF objdata, OOXML external rels, OLE VBA, HTML beacons, email tracking pixels, CSV formula injection, XML XXE, archive recursion |
| embedded | inventory | `canary-scan-embedded.json` + `canary-scan-embedded/` | Extract embedded objects: pdfimages, rtfobj, OOXML parts, OLE streams |
| stego | inventory (image bucket) | `canary-scan-stego.json` | steghide info; opt-in stegseek cracking |
| uniqueness | inventory + metadata | `canary-scan-unique-clusters.json` | Cluster by `(bucket, page_count, producer, creator)` → qpdf --qdf diff (PDF), unzip-diff core.xml (OOXML), compare -metric AE (image) |
| report | all stage artefacts | `canary-scan-report.json` (+ `.csv` / `.sarif`) | Merge, deduplicate, filter by `--severity-threshold`, emit in requested format |

### File-Type Buckets (12 + 1 opt-in)

`pdf`, `rtf`, `ooxml`, `odf`, `ole`, `html`, `email`, `image`, `csv`, `xml`, `archive`, `other`, `specialized` (opt-in via `--enable-specialized`)

---

## Development Setup

**⚠️ CRITICAL: NEVER create a local `.venv` folder in this repository.**

Prefer `make` targets (e.g. `make test`); the Makefile's `UV` prefix sets the required env vars. For raw `uv`:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv run pytest tests/ -v
```

For first-time setup, sync, etc., see `.agent/workflows/dev-setup.md`.

---

## Additional Documentation

- **[`.agent/README.md`](../README.md)** — Agent index, rules, skills, workflows, project spec.
- **[`development-phase.md`](development-phase.md)** — Pre-alpha development constraints.
- **[`architecture-decisions.md`](architecture-decisions.md)** — Architecture Decision Records (ADRs).
- **[`dev-setup.md`](../workflows/dev-setup.md)** — Detailed environment setup steps.
- **[`uv-commands.md`](../workflows/uv-commands.md)** — How to run uv correctly.
