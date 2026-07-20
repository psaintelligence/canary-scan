# Package Age Limit

## Install Packages At Least 14 Days Old

**⚠️ CRITICAL RULE: NEVER install packages or updates published less than 14 days ago. This protects against supply chain attacks and malicious package updates.**

### Required Actions

- ✅ **ALWAYS** verify publish date on registry info before installing any new package or upgrading existing ones.
- ✅ **ALWAYS** check that the specific version to be installed was released at least 14 days ago.
- ✅ **ALWAYS** ensure `pyproject.toml` has `exclude-newer` configured under `[tool.uv]` to at least `14 days` (e.g., `30 days` is acceptable, but less than `14 days` is prohibited).

### Prohibited Actions

- ❌ **NEVER** install the `@latest` version of a package if it was published within the last 14 days. Specifying an older, stable version is required instead.
- ❌ **NEVER** modify `pyproject.toml` to reduce the `exclude-newer` setting under `[tool.uv]` to less than `14 days` (e.g., setting to `7 days` or removing it is prohibited).

### Why this exists

Malicious packages or compromised updates are usually detected and revoked within the first two weeks of publication. Waiting at least 14 days greatly reduces the risk of installing compromised packages.
