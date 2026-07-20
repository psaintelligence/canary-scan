.PHONY: help setup vendor sync sync-frozen test test-verbose lint format lint-fix run fixtures clean bump-patch bump-minor docs-sync docs-build docs-serve

.DEFAULT_GOAL := help

# UV execution prefix with environment isolation (prevents local .venv leakage)
UV := UV_PROJECT_ENVIRONMENT=$(HOME)/.local/venvs/canary-scan UV_CACHE_DIR=/tmp/.uv-cache-canary-scan UV_LINK_MODE=copy uv

# Extra args forwarded to the underlying tool. Override on the command line, e.g.:
#   make run ARGS="deps --fix-hints"
#   make test ARGS="tests/test_remote_refs.py -k canary"
#   make lint ARGS="--statistics"
ARGS ?=

# Show help menu of available commands
help:
	@echo "Available commands:"
	@echo "  make setup        - One-time dev setup: create venv, vendor assets, sync deps"
	@echo "  make vendor       - Fetch vendored third-party scripts (Didier Stevens suite)"
	@echo "  make sync         - Sync Python dependencies"
	@echo "  make sync-frozen  - Re-sync dependencies from frozen lockfile"
	@echo "  make test         - Run tests (ARGS=\"<pytest args>\" to filter)"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make lint         - Run linting checks (ruff) (ARGS=\"<ruff args>\")"
	@echo "  make format       - Format code (ruff)"
	@echo "  make lint-fix     - Auto-fix lint issues and format"
	@echo "  make run          - Run canary-scan CLI (RUN_ARGS=\"<cli args>\"; default --guide)"
	@echo "  make deps         - canary-scan deps  (ARGS=\"<args>\" to pass flags)"
	@echo "  make scan         - canary-scan scan  (ARGS=\"<args>\" to pass flags)"
	@echo "  make stage        - canary-scan stage (ARGS=\"<args>\" to pass flags)"
	@echo "  make report       - canary-scan report (ARGS=\"<args>\" to pass flags)"
	@echo "  make fixtures     - Generate test fixtures"
	@echo "  make clean        - Clean build/test artifacts"
	@echo "  make bump-patch   - Bump the patch version (e.g. 0.1.4 -> 0.1.5)"
	@echo "  make bump-minor   - Bump the minor version (e.g. 0.1.4 -> 0.2.0)"
	@echo "  make docs-sync    - Sync documentation dependencies"
	@echo "  make docs-build   - Build documentation site"
	@echo "  make docs-serve   - Serve documentation locally"

# One-time dev setup: create venv, vendor assets, sync dependencies
setup:
	@echo "Initializing isolated virtual environment..."
	$(UV) venv --clear $(HOME)/.local/venvs/canary-scan
	@$(MAKE) vendor
	@echo "Syncing dependencies..."
	$(UV) sync --extra test

# Fetch vendored third-party scripts (Didier Stevens suite)
vendor:
	bash src/canary_scan/bundled/fetch.sh

# Sync Python dependencies
sync:
	$(UV) sync --extra test

# Re-sync frozen (after lockfile changes)
sync-frozen:
	$(UV) sync --extra test --frozen

# Run tests
test:
	$(UV) run --extra test pytest -vv tests/ $(ARGS)

# Run tests verbose
test-verbose:
	$(UV) run --extra test pytest tests/ -v $(ARGS)

# Lint
lint:
	$(UV) run --extra test ruff check src/canary_scan/ tests/ $(ARGS)

# Format
format:
	$(UV) run --extra test ruff format src/canary_scan/ tests/

# Auto-fix lint issues and format
lint-fix:
	$(UV) run --extra test ruff check --fix src/canary_scan/ tests/
	$(UV) run --extra test ruff format src/canary_scan/ tests/

# Run canary-scan CLI (override: make run RUN_ARGS="deps --fix-hints")
RUN_ARGS ?= --guide
run:
	$(UV) run --extra test canary-scan $(RUN_ARGS)

# Subcommand shortcuts — equivalent to: make run RUN_ARGS="<cmd> $(ARGS)"
# Examples: make deps, make deps ARGS="--fix-hints", make scan ARGS="/path --bucket pdf"
deps scan stage report:
	$(UV) run --extra test canary-scan $@ $(ARGS)

# Generate test fixtures
fixtures:
	$(UV) run --extra test python tests/generate_fixtures.py tests/fixtures

# Clean build/test artifacts
clean:
	rm -rf .canary-scan canary-scan-out dist build *.egg-info docs/site docs/.venv
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +
	find . -type d -name .ruff_cache -exec rm -rf {} +

# Bump the patch version number (e.g. 0.1.4 -> 0.1.5)
bump-patch:
	@$(UV) run --extra test python -c 'import re; from pathlib import Path; p = Path("src/canary_scan/__init__.py"); c = p.read_text(); m = re.search(r"^__version__\s*=\s*\"([^\"]+)\"", c, re.MULTILINE); v = m.group(1); parts = v.split("."); n = f"{parts[0]}.{parts[1]}.{int(parts[2])+1}"; p.write_text(re.sub(r"^__version__\s*=\s*\"[^\"]+\"", f"__version__ = \"{n}\"", c, flags=re.MULTILINE)); print(f"Bumped patch version: {v} -> {n}")'

# Bump the minor version number (e.g. 0.1.4 -> 0.2.0)
bump-minor:
	@$(UV) run --extra test python -c 'import re; from pathlib import Path; p = Path("src/canary_scan/__init__.py"); c = p.read_text(); m = re.search(r"^__version__\s*=\s*\"([^\"]+)\"", c, re.MULTILINE); v = m.group(1); parts = v.split("."); n = f"{parts[0]}.{int(parts[1])+1}.0"; p.write_text(re.sub(r"^__version__\s*=\s*\"[^\"]+\"", f"__version__ = \"{n}\"", c, flags=re.MULTILINE)); print(f"Bumped minor version: {v} -> {n}")'

# UV configuration for documentation (isolated to prevent package dev conflict)
DOCS_UV = UV_PROJECT_ENVIRONMENT=$(HOME)/.local/venvs/canary-scan-docs UV_CACHE_DIR=/tmp/.uv-cache-canary-scan-docs UV_LINK_MODE=copy uv

# Sync documentation dependencies
docs-sync:
	cd docs && $(DOCS_UV) sync

# Build documentation site
docs-build:
	cd docs && $(DOCS_UV) run mkdocs build

# Serve documentation locally
docs-serve:
	cd docs && $(DOCS_UV) run mkdocs serve
