---
description: Guidelines for running uv commands to prevent creating local .venv folders.
---

# uv Command Guidelines

When running `uv` commands (like `uv run pytest`, `uv run ruff`, etc.), you **MUST** set environment variables that redirect the virtual environment to `${HOME}/.local/venvs/canary-scan` and the cache directory to `/tmp`. This keeps the repository free of a local `.venv`.

## 1. Recommended Method: Use the Makefile

The Makefile defines a `UV` prefix variable with exactly the required environment variables, so `make <target>` is the safest entry point:

```bash
make test        # = uv run --extra test pytest -vv tests/
make sync        # = uv sync --extra test
make lint        # = uv run --extra test ruff check src/canary_scan/ tests/
make format      # = uv run --extra test ruff format src/canary_scan/ tests/
make lint-fix    # = ruff check --fix && ruff format
make run         # = uv run --extra test canary-scan --guide
make fixtures    # = uv run --extra test python tests/generate_fixtures.py tests/fixtures
```

## 2. Raw uv Commands

If you need to invoke `uv` directly (no Make target fits), use this exact multiline prefix:

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv <command>
```

**Examples:**

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv run pytest tests/ -v
```

```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv sync --extra test
```

Tip: define a shell alias to avoid repeating the prefix:

```bash
alias csuv='UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan UV_CACHE_DIR=/tmp/.uv-cache-canary-scan UV_LINK_MODE=copy uv'
# then: csuv run pytest tests/ -v
```

## Required Environment Variables

| Variable | Value | Why |
|---|---|---|
| `UV_PROJECT_ENVIRONMENT` | `${HOME}/.local/venvs/canary-scan` | Shared project venv outside the repo. |
| `UV_CACHE_DIR` | `/tmp/.uv-cache-canary-scan` | Isolated uv cache in `/tmp`. |
| `UV_LINK_MODE` | `copy` | Avoids symlink issues across mounts/network file systems. |

## Common Mistakes

- **Running bare `uv` without the env prefix.** This creates `.venv/` in the repository and ignores the project's required cache/link settings.
- **Using `--group dev` instead of `--extra test`.** `canary-scan` defines dev/test dependencies under `[project.optional-dependencies] test`, not a dependency group.
- **Forgetting `--extra test`.** Without it, `pytest`, `reportlab`, and fixture-generation libs will not be installed.
