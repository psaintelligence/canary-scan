# Architecture Decisions

Decisions made about the `canary-scan` codebase, with context and rationale.
Format: lightweight ADR — Status / Context / Decision / Consequences.

---

## ADR-001: Python 3.10+ (broad LTS compatibility)

**Status:** Accepted (revised 2026-07; supersedes original 3.12-only target)

**Context:** canary-scan targets forensic/analysis VMs and CI matrices across modern Python releases. Original target was 3.12 (Ubuntu 24.04 LTS), but the project now supports 3.10 through 3.14 to cover older LTS hosts and latest stable alike.

**Decision:** `requires-python = ">=3.10"`. Use `match` statements (3.10+), `X | None` type hints (3.10+), and `from __future__ import annotations` for forward-reference safety. Do not use 3.13-only features. CI matrix tests 3.10 / 3.11 / 3.12 / 3.13 / 3.14.

**Consequences:** Broader compatibility across LTS distributions. Skills like `python-pro` that reference 3.13 features should be adapted when applied to this project.

---

## ADR-002: Typer CLI (not Click or argparse)

**Status:** Accepted

**Context:** The CLI has 6 subcommands (`scan`, `stage`, `verify`, `deps`, `report`, `--guide`) with many shared options (20+ flags). Rich output is desired for tables (dep matrix, summary).

**Decision:** Use `typer[all]` which provides Click-based CLI with Rich integration, type-safe options via enums, and `no_args_is_help` behaviour.

**Consequences:** Adds `typer` + `rich` as required deps. CLI auto-generates `--help` and shell completion. Tests can invoke the app directly via `typer.testing.CliRunner`.

---

## ADR-003: JSONL as default output (not CSV or pretty JSON)

**Status:** Accepted

**Context:** The tool is designed to be chained into other processes (SIEM ingest, `jq` pipelines, DefectDojo). Pretty-printed JSON is not streamable; CSV loses nested structure.

**Decision:** Default `--format json` emits JSONL (one finding object per line). CSV and SARIF are opt-in. All stage intermediates are also JSONL `.json`. Human review via `jq`.

**Consequences:** `io.py` has one JSONL writer for all stages. `--stdout` emits the same JSONL stream for piping. Final report file is `canary-scan-report.json` (JSONL content).

---

## ADR-004: Warn-only read-only mount check (revised)

**Status:** Accepted (revised 2026-07; supersedes original strict-exit decision)

**Context:** The original decision required a read-only mount and exited with code 3 on any writable datasource. In practice this blocked legitimate workflows where the practitioner has already snapshotted / imaged the data but has not remounted read-only, and the strict-exit behaviour forced users to bypass the tool entirely (running raw `strings` / `pdftotext` on the writable tree with no canary checks at all).

The read-only recommendation remains best practice for evidence integrity, but enforcing it via hard exit pushed users toward less-safe alternatives.

**Decision:** `safety.check_readonly_mount()` runs `findmnt -no OPTIONS <path>` and emits a prominent red/yellow warning panel via `err_console` when the mount is writable, when `findmnt` cannot confirm the mount options, or when `findmnt` itself is missing. The scan then proceeds. Exit code is **not** altered — this is a warning, not a gate.

**Consequences:** Users are nudged toward read-only mounts (the warning is loud) but can proceed on writable trees when they have accepted the integrity risk. README, `--guide`, and the warning text itself all recommend `archivemount -o ro` or `mount -o remount,ro`. No bypass flag is needed because there is nothing to bypass.

---

## ADR-005: Bundled Didier Stevens scripts (not pip/PATH dependency)

**Status:** Accepted

**Context:** The Didier Stevens suite (`pdfid.py`, `pdf-parser.py`, `rtfdump.py`) is not on PyPI and not in apt. In air-gapped environments, network access to fetch them at runtime is unavailable.

**Decision:** Bundle the scripts inside `src/canary_scan/bundled/` with provenance headers. `src/canary_scan/bundled/fetch.sh` fetches them from the Didier Stevens Beta GitHub repo at build time, records commit SHA + version + date in `VERSIONS.txt`. Invoked via `python -m canary_scan.bundled.pdfid`.

**Consequences:** Package size increases by ~50KB. License compliance via `src/canary_scan/bundled/README.md` (BSD 2-Clause). Updates require re-running `make vendor`.

---

## ADR-006: flock + runs[] audit trail for re-runnability

**Status:** Accepted

**Context:** Investigators may re-run scans after installing new deps or fixing partial failures. Concurrent runs on the same outdir would corrupt state. Audit trail needed for chain-of-custody.

**Decision:** (1) `--resume` is default — stages with `exit_code==0` are skipped; `--force` re-runs all. (2) `fcntl.flock` on `canary-scan.lock` in outdir; exit 5 if locked. (3) `canary-scan-state.json` keeps an append-only `runs[]` array with run_id, timestamps, stages, CLI args.

**Consequences:** No data loss on re-run. Clear error on concurrent access. Audit trail grows with each run — documented as expected behaviour for evidence handling.

---

## ADR-007: uv + hatchling + ruff (not setuptools/pip)

**Status:** Accepted

**Context:** The `.agent` rules mandate uv for dependency management with `exclude-newer = "14 days ago"` for supply-chain safety. The original build used setuptools.

**Decision:** Migrated `pyproject.toml` to hatchling build backend with `[tool.uv] exclude-newer` and ruff for lint/format. Dev deps under `[project.optional-dependencies] test`. All `make` targets invoke `uv` via a `UV` env-prefix variable defined in the Makefile (no wrapper script).

**Consequences:** No local `.venv` (venv at `${HOME}/.local/venvs/canary-scan`). `make sync` / `make test` / `make lint` use the `UV` prefix. CI workflow uses `uv` directly (env vars set inline). For raw `uv` outside `make`, set the same env vars inline.

---

## ADR-008: 12 file-type buckets with per-bucket routing in remote-refs and uniqueness stages

**Status:** Accepted

**Context:** A document dump contains heterogeneous file types with different canary surfaces. A one-size-fits-all scanner would miss type-specific vectors (e.g. OOXML external rels, CSV formula injection, XML XXE, email tracking pixels).

**Decision:** `type_detect.py` classifies each file into one of 12 buckets (pdf, rtf, ooxml, odf, ole, html, email, image, csv, xml, archive, other). remote-refs and uniqueness stages route to per-bucket functions via `match bucket:`. `other` files get inventory/metadata stages only + an INFO finding.

**Consequences:** Adding a new file type requires: extension mapping in `config.py`, bucket enum, and a handler function in remote-refs stage (+ optionally embedded, stego, or uniqueness). Well-isolated, testable per-bucket.

---

## ADR-009: SARIF output for security tooling integration

**Status:** Accepted

**Context:** Findings need to be ingestible by GitHub Security tab, DefectDojo, and other SARIF-compatible security platforms.

**Decision:** `--format sarif` emits OASIS SARIF 2.1.0 with `run.tool.driver.name = "canary-scan"`, `ruleId` from category taxonomy, `level` mapped from severity (critical/high → error, medium → warning, low/info → note).

**Consequences:** `io.py` has a SARIF writer (~50 lines). Rules catalog generated from `CATEGORY_INFO` in `config.py`. SARIF `helpUri` points to README report-interpretation section.
