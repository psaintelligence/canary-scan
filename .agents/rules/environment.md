# Environment Guidelines

## Strictly No Local `.venv`

**⚠️ CRITICAL RULE: NEVER create a local `.venv` directory inside the repository.**

All dependency management and execution must be isolated from the repository path to ensure a clean monorepo experience and prevent state pollution. 

### Enforcing the Rule
Whenever you use `uv` to install dependencies, run scripts, execute tests, or start the application, you **MUST** prefix the command with environment variables that point the virtual environment to `${HOME}/.local/venvs/canary-scan` and the cache to the `/tmp/` directory, and explicitly use copy linking.

> [!TIP]
> **Recommended:** Use the Makefile targets (`make sync`, `make test`, `make lint`, `make run`). The Makefile defines a `UV` prefix variable with exactly the required environment variables, so targets are the safest entry point and avoid format-sensitive inline prefixes.

> [!NOTE]
> A Dockerfile is available at the project root for containerized execution. Inside the container, the virtual environment is built at `/app/.venv` instead of the local user path.

If running `uv` directly, you must use this exact multiline prefix structure:
```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv <command>
```

**Example (Running the CLI):**
```bash
UV_PROJECT_ENVIRONMENT=${HOME}/.local/venvs/canary-scan \
UV_CACHE_DIR=/tmp/.uv-cache-canary-scan \
UV_LINK_MODE=copy \
uv run canary-scan --guide
```

Failure to use this prefix may result in a `.venv` being created in the workspace, which is strictly prohibited.
