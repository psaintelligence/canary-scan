.PHONY: help setup sync vendor test test-verbose lint format lint-fix run clean docs-sync docs-build docs-serve

.DEFAULT_GOAL := help

# Show help menu of available commands
help:
	@echo "Available commands:"
	@echo "  make setup        - One-time dev setup: vendor assets + sync dependencies"
	@echo "  make vendor       - Fetch vendored third-party scripts"
	@echo "  make sync         - Sync Python dependencies"
	@echo "  make sync-frozen  - Re-sync dependencies from frozen lockfile"
	@echo "  make test         - Run tests"
	@echo "  make test-verbose - Run tests with verbose output"
	@echo "  make lint         - Run linting checks (ruff)"
	@echo "  make format       - Format code (ruff)"
	@echo "  make lint-fix     - Auto-fix linting issues"
	@echo "  make run          - Run canary-scan CLI"
	@echo "  make fixtures     - Generate test fixtures"
	@echo "  make clean        - Clean build/test artifacts"
	@echo "  make docs-sync    - Sync documentation dependencies"
	@echo "  make docs-build   - Build documentation site"
	@echo "  make docs-serve   - Serve documentation locally"

# One-time dev setup: vendor assets + sync dependencies
setup: vendor sync

# Fetch vendored third-party scripts (Didier Stevens suite)
vendor:
	bash src/canary_scan/bundled/fetch.sh

# Sync Python dependencies
sync:
	./scripts/uv-exec sync --extra test

# Re-sync frozen (after lockfile changes)
sync-frozen:
	./scripts/uv-exec sync --extra test --frozen

# Run tests
test:
	./scripts/uv-exec run pytest -vv tests/

# Run tests verbose
test-verbose:
	./scripts/uv-exec run pytest tests/ -v

# Lint
lint:
	./scripts/uv-exec run ruff check src/canary_scan/ tests/

# Format
format:
	./scripts/uv-exec run ruff format src/canary_scan/ tests/

# Auto-fix lint issues
lint-fix:
	./scripts/uv-exec run ruff check --fix src/canary_scan/ tests/

# Run canary-scan CLI
run:
	./scripts/uv-exec run canary-scan --guide

# Generate test fixtures
fixtures:
	./scripts/uv-exec run python tests/generate_fixtures.py tests/fixtures

# Clean build/test artifacts
clean:
	rm -rf .canary-scan canary-scan-out dist build *.egg-info docs/site docs/.venv
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type d -name .pytest_cache -exec rm -rf {} +

# UV configuration for documentation
DOCS_UV = UV_PROJECT_ENVIRONMENT=$${HOME}/.local/venvs/canary-scan-docs UV_CACHE_DIR=/tmp/.uv-cache-canary-scan-docs UV_LINK_MODE=copy uv

# Sync documentation dependencies
docs-sync:
	cd docs && $(DOCS_UV) sync

# Build documentation site
docs-build:
	cd docs && $(DOCS_UV) run mkdocs build

# Serve documentation locally
docs-serve:
	cd docs && $(DOCS_UV) run mkdocs serve
