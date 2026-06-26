# `report` command

Re-render the final report from existing stage artefacts without re-scanning the data-source. Use this to change the output format, adjust the severity threshold, or apply an updated allowlist.

## Usage

```bash
canary-scan report [OPTIONS]
```

The command reads all intermediate stage artefacts from the output directory (`canary-scan-inventory.json`, `canary-scan-metadata.json`, etc.), deduplicates the findings, applies the filter engine, and writes a fresh final report.

## Examples

```bash
# Re-render the report with a stricter severity filter
canary-scan report --severity-threshold high

# Re-render as SARIF for upload to GitHub Security tab
canary-scan report --format sarif

# Emit all three formats at once
canary-scan report --format all

# Apply an updated allowlist without re-scanning
canary-scan report --allowlist updated-allowlist.json

# Read from a non-default output directory
canary-scan report -o /evidence/case-123/canary-scan

# Stream findings to stdout
canary-scan report --stdout --severity-threshold critical
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `-o`, `--outdir` | `PATH` | `.canary-scan` | Output directory containing existing stage artefacts. |
| `-f`, `--format` | `json\|csv\|sarif\|all` | `json` | Output format for the regenerated report. |
| `--stdout` | flag | off | Emit findings as JSONL to stdout instead of (or in addition to) writing files. |
| `--severity-threshold` | `info\|low\|medium\|high\|critical` | `info` | Only include findings at or above this severity level. |
| `--allowlist` | `PATH` | — | Path to a JSON or plain-text allowlist file. Matching findings are suppressed. |
| `--denylist` | `PATH` | — | Path to a JSON or plain-text denylist file. Matching indicators are force-flagged. |

## Output files

| `--format` | File written | Description |
|---|---|---|
| `json` | `canary-scan-report.json` | JSONL stream — one finding per line |
| `csv` | `canary-scan-report.csv` | Flattened tabular — `extras` field serialised as `extras_json` |
| `sarif` | `canary-scan-report.sarif` | OASIS SARIF 2.1.0 for security tooling |
| `all` | All three above | Writes all formats in a single pass |

!!! tip "Re-render without re-scanning"
    If you have already run `canary-scan scan` and only want to change the format or severity filter, `canary-scan report` is much faster than re-running the full pipeline. The stage artefacts from the previous scan are reused directly.
