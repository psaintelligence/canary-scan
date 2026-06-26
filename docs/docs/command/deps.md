# `deps` command

Check and report on the external binary and Python package dependencies required by `canary-scan`. Useful for verifying your environment before a scan and for generating installation hints when something is missing.

## Usage

```bash
canary-scan deps [OPTIONS]
```

## Examples

```bash
# Show a dependency status table
canary-scan deps

# Show install commands for any missing dependencies
canary-scan deps --fix-hints

# Include specialised dependencies in the check (audio, video, fonts, DICOM)
canary-scan deps --enable-specialized

# Treat optional dependencies as required (exit code 2 if any are missing)
canary-scan deps --strict-deps
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `--fix-hints` | flag | off | Print installation commands for any missing dependencies rather than the status table. |
| `--enable-specialized` | flag | off | Include Tier 3 specialised dependencies (fonttools, pydicom, mutagen, ffprobe, pyOneNote) in the check. |
| `--strict-deps` | flag | off | Treat missing optional dependencies as errors. Exits with code 2 if any are absent. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | All required (and, with `--strict-deps`, optional) dependencies are present |
| 2 | One or more required dependencies are missing |

## Dependency tiers

Dependencies are classified into three tiers:

- **Required** — the scan cannot run without these. Missing required deps exit with code 2.
- **Optional** — reduce detection coverage when absent but do not abort the scan.
- **Specialised** — enabled only with `--enable-specialized`. Requires `pip install "canary-scan[specialized]"`.

See the [Install guide](../install.md) for the complete dependency matrix and installation instructions.
