---
description: How to set up the development environment for the canary-scan project.
---

# Dev Environment Setup

## Why This Matters

`canary-scan` uses `uv` for dependency management. The project **must not** create a repository-local `.venv`; environment variables redirect uv to a shared venv and cache. Prefer `make` targets (the Makefile defines a `UV` prefix with the required env vars); for raw `uv` commands, use the env-var prefix documented in `.agents/workflows/uv-commands.md`.

## One-Time Dev Setup

```bash
make setup
```

This does three things:

1. Creates the isolated venv at `${HOME}/.local/venvs/canary-scan` (`uv venv --clear`).
2. `make vendor` — fetches the vendored Didier Stevens scripts (`pdfid.py`, `pdf-parser.py`, `rtfdump.py`) into `src/canary_scan/bundled/`.
3. `make sync` — runs `uv sync --extra test` (with the `UV` env prefix) to install the package and test dependencies.

## Manual Steps (if not using Make)

### 1. Vendor third-party scripts

```bash
bash src/canary_scan/bundled/fetch.sh
```

This clones the Didier Stevens Beta repository, copies `pdfid.py`, `pdf-parser.py`, and `rtfdump.py` into `src/canary_scan/bundled/` with provenance headers, and writes `VERSIONS.txt`.

### 2. Install Python dependencies

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv sync --extra test
```

`--extra test` installs `pytest`, `reportlab`, `python-docx`, `openpyxl`, and `python-pptx` from `[project.optional-dependencies] test` in `pyproject.toml`.

### 3. Generate test fixtures

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv run --extra test python tests/generate_fixtures.py tests/fixtures
```

Creates synthetic canary files (PDF with /URI, RTF with objdata, DOCX with external link, CSV with formula injection, etc.) for the test suite.

## Re-Sync After pyproject.toml or uv.lock Changes

```bash
make sync
```

Or manually:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv sync --extra test
```

## Common Dev Commands

Prefer `make <target>`. For raw `uv` invocations, prefix every command with the env vars shown above (or define a `csuv` alias — see `uv-commands.md`).

```bash
# Run tests
make test
# raw: uv run --extra test pytest tests/ -v   (with env prefix)

# Lint
make lint
# raw: uv run --extra test ruff check src/canary_scan/ tests/

# Format
make format
# raw: uv run --extra test ruff format src/canary_scan/ tests/

# Auto-fix lint issues and format
make lint-fix
# raw: ruff check --fix && ruff format          (both with env prefix)

# Run the CLI
make run
# raw: uv run --extra test canary-scan --guide

# Generate fixtures
make fixtures
# raw: uv run --extra test python tests/generate_fixtures.py tests/fixtures
```

## System Dependencies (Required at Runtime)

These are external binaries not managed by uv:

```bash
sudo apt install libimage-exiftool-perl qpdf poppler-utils mupdf-tools \
    ripgrep unzip p7zip-full
```

Optional: `unrar`, `imagemagick`, `steghide`, `stegseek`, `peepdf`, `pngcheck`, `jq`.

Run `canary-scan deps` to check and `canary-scan deps --fix-hints` for install hints.

## DO NOT Do This

```bash
# Wrong — creates a local .venv and ignores project env config
uv sync
uv run pytest

# Wrong — uses deprecated dependency-group syntax
uv sync --group dev
```

See `.agent/workflows/uv-commands.md` for the full rationale and raw uv invocations.
