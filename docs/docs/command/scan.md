# `scan` command

Run the full canary-scan analysis pipeline across all seven stages on a target data-source directory.

## Usage

```bash
canary-scan scan [OPTIONS] DATASOURCE
```

`DATASOURCE` is the path to the read-only mounted data-source directory. See the [Workflow guide](../workflow.md) for how to mount a data-source safely.

## Examples

```bash
# Full scan with defaults
canary-scan scan /mnt/datasource

# Write output to a specific directory
canary-scan scan /mnt/datasource -o /evidence/case-123/canary-scan

# Emit critical findings to stdout (for piping to SIEM)
canary-scan scan /mnt/datasource --stdout --severity-threshold critical

# SARIF output for GitHub Security tab
canary-scan scan /mnt/datasource --format sarif

# Enable specialised file types and steganography brute-forcing
canary-scan scan /mnt/datasource --enable-specialized --crack-steg /wordlists/rockyou.txt

# Suppress known-safe domains
canary-scan scan /mnt/datasource --allowlist allowlist.json

# Force a full re-run, ignoring previous progress
canary-scan scan /mnt/datasource --force
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `-o`, `--outdir` | `PATH` | `.canary-scan` | Output directory for stage artefacts and the final report. |
| `-f`, `--format` | `json\|csv\|sarif\|all` | `json` | Final report format. `all` writes all three formats simultaneously. |
| `--stdout` | flag | off | Emit findings as JSONL to stdout in addition to writing files. |
| `--severity-threshold` | `info\|low\|medium\|high\|critical` | `info` | Only include findings at or above this severity in the final report. |
| `--workers` | `INTEGER` | `8` | Number of parallel workers for CPU-bound scanner stages. |
| `--resume` / `--no-resume` | flag | `--resume` | Skip stages that completed successfully in a prior run. Use `--no-resume` to re-run everything. |
| `--force` | flag | off | Re-run all stages regardless of prior state, appending a new audit entry. |
| `--strict-deps` | flag | off | Treat missing optional dependencies as fatal (exit code 2). |
| `--keep-tmp` | flag | off | Retain the temporary extraction directory after the scan completes. |
| `--crack-steg` | `PATH` | — | Path to a passphrase wordlist for opt-in steganography brute-forcing via `stegseek`. |
| `--fuzzy-cluster` | flag | off | Allow producer/creator version differences when clustering near-duplicates in the uniqueness stage. |
| `--min-cluster-size` | `INTEGER` | `2` | Minimum number of near-duplicate documents required to form a uniqueness cluster. |
| `--max-archive-depth` | `INTEGER` | `3` | Maximum depth for recursive archive extraction (zip-in-zip etc.). |
| `--enable-specialized` | flag | off | Enable Tier 3 specialised file types: audio, video, fonts, DICOM, OneNote. Requires `canary-scan[specialized]`. |
| `--allowlist` | `PATH` | — | Path to a JSON or plain-text allowlist file. Matching findings are suppressed. |
| `--denylist` | `PATH` | — | Path to a JSON or plain-text denylist file. Matching indicators are force-flagged. |
| `--verbose` / `--quiet` | flag | off | Increase or reduce console output verbosity. |

## Pipeline stages run

All seven stages execute in sequence:

| # | Stage | Description |
|---|---|---|
| 1 | `inventory` | Walks the filesystem, computes SHA-256 hashes, identifies MIME types, classifies into buckets |
| 2 | `metadata` | Extracts metadata via `exiftool`, scans for tracking URLs, GPS coordinates, PII, and device identifiers |
| 3 | `remote-refs` | Inspects document structure for XXE, tracking pixels, remote template links, formula injections, OLE hyperlinks |
| 4 | `embedded` | Extracts nested binaries, raster images, OLE/ActiveX objects |
| 5 | `stego` | Detects steganographic carriers via `steghide`/`stegseek`, QR code URL detection, EXIF thumbnail mismatch |
| 6 | `uniqueness` | Near-duplicate clustering to identify per-recipient canary values |
| 7 | `report` | Merges and deduplicates findings from all stages, filters by severity, emits the final report |

To run a single stage, use the [`stage` command](stage.md).
