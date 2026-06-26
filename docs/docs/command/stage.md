# `stage` command

Run a single stage of the pipeline rather than the full seven-stage sequence. Useful for re-running a specific stage, debugging, or incremental scanning workflows.

## Usage

```bash
canary-scan stage [OPTIONS] STAGE_NAME DATASOURCE
```

`STAGE_NAME` is one of: `inventory`, `metadata`, `remote-refs`, `embedded`, `stego`, `uniqueness`, `report`.

`DATASOURCE` is the path to the read-only mounted data-source directory.

## Examples

```bash
# Re-run only the metadata stage
canary-scan stage metadata /mnt/datasource

# Re-run the remote-refs stage, writing output to a custom directory
canary-scan stage remote-refs /mnt/datasource -o /evidence/case-123/canary-scan

# Run the report stage with a stricter severity threshold
canary-scan stage report /mnt/datasource --severity-threshold high

# Run a single stage and force it even if it previously completed
canary-scan stage stego /mnt/datasource --force
```

## Options

| Option | Type | Default | Description |
|---|---|---|---|
| `-o`, `--outdir` | `PATH` | `.canary-scan` | Output directory for stage artefacts. |
| `-f`, `--format` | `json\|csv\|sarif\|all` | `json` | Report format (applies to `report` stage only). |
| `--stdout` | flag | off | Emit findings as JSONL to stdout (applies to `report` stage only). |
| `--severity-threshold` | `info\|low\|medium\|high\|critical` | `info` | Only include findings at or above this severity (applies to `report` stage only). |
| `--workers` | `INTEGER` | `8` | Number of parallel workers for the stage. |
| `--resume` / `--no-resume` | flag | `--resume` | Skip this stage if it previously completed successfully. |
| `--force` | flag | off | Re-run the stage regardless of prior state. |
| `--strict-deps` | flag | off | Treat missing optional dependencies as fatal. |
| `--keep-tmp` | flag | off | Retain the temporary extraction directory. |
| `--crack-steg` | `PATH` | — | Wordlist path for stegseek brute-forcing (applies to `stego` stage only). |
| `--fuzzy-cluster` | flag | off | Allow version drift in near-duplicate clustering (applies to `uniqueness` stage only). |
| `--min-cluster-size` | `INTEGER` | `2` | Minimum cluster size for uniqueness analysis. |
| `--max-archive-depth` | `INTEGER` | `3` | Maximum archive recursion depth (applies to `remote-refs` and `embedded` stages). |
| `--enable-specialized` | flag | off | Enable Tier 3 specialised file types. |
| `--verbose` / `--quiet` | flag | off | Increase or reduce console output verbosity. |

## Available stages

| Stage | Output artefact | Description |
|---|---|---|
| `inventory` | `canary-scan-inventory.json` | File walk, SHA-256 hashes, MIME types, bucket classification |
| `metadata` | `canary-scan-metadata.json` | exiftool extraction, tracking URLs, GPS/serial/PII indicators |
| `remote-refs` | `canary-scan-remote-refs.json` | XXE, tracking pixels, formula injections, remote template links, OLE hyperlinks |
| `embedded` | `canary-scan-embedded.json` | Nested binaries, OLE/ActiveX objects, raster image extraction |
| `stego` | `canary-scan-stego.json` | Steghide/stegseek carrier checks, QR code URL detection, EXIF thumbnail mismatch |
| `uniqueness` | `canary-scan-unique-clusters.json` | Near-duplicate clustering to surface per-recipient canary values |
| `report` | `canary-scan-report.json` (and `.csv`, `.sarif`) | Merge, deduplicate, filter by severity, emit final report |

!!! note
    The `inventory` stage must run first — all subsequent stages consume `canary-scan-inventory.json`. If you use `--resume` (the default), the inventory will be reused automatically.
