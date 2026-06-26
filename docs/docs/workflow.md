# Workflow Guide

## 1. Mount your data-source read-only

Running against a read-only mount protects the integrity of the evidence and prevents any tool bug from modifying your data-source. `canary-scan` checks the mount at startup and warns if it detects a writable path.

### Using `archivemount` (recommended for archives)

`archivemount` is a FUSE module that presents archive files as a virtual read-only filesystem. Supports `.tar.gz`, `.zip`, `.iso`, `.7z`, `.rar`:

```bash
sudo apt install archivemount fuse

mkdir /mnt/datasource
archivemount -o ro datasource.tar.gz /mnt/datasource

# Unmount when finished
fusermount -u /mnt/datasource
```

### Using `mount` (for directories already on disk)

```bash
# If the data-source is on its own filesystem
mount -o remount,ro /dev/sdX /mnt/datasource

# If it's a subdirectory on an existing filesystem, bind-mount it
mount --bind /path/to/datasource /mnt/datasource
mount -o remount,ro /mnt/datasource
```

---

## 2. Check dependencies

```bash
canary-scan deps
canary-scan deps --fix-hints     # show install commands for anything missing
```

Missing **required** dependencies cause exit code 2. Missing **optional** dependencies reduce detection coverage but do not abort the scan.

---

## 3. Run the scan

```bash
# Full pipeline — all seven stages
canary-scan scan /mnt/datasource

# Write output to a specific evidence directory
canary-scan scan /mnt/datasource -o /evidence/case-123/canary-scan

# Only run specific stages
canary-scan stage metadata /mnt/datasource
canary-scan stage remote-refs /mnt/datasource

# Enable specialised file types (audio, video, fonts, DICOM, OneNote)
canary-scan scan /mnt/datasource --enable-specialized

# Opt-in to steganography brute-forcing with a passphrase wordlist
canary-scan scan /mnt/datasource --crack-steg /wordlists/rockyou.txt
```

---

## 4. Review findings

### JSON (default)

The report is JSONL — one finding per line — written to `.canary-scan/canary-scan-report.json`:

```bash
# All critical findings
jq '.[] | select(.severity=="critical")' .canary-scan/canary-scan-report.json

# All findings for a specific file
jq '.[] | select(.file | contains("sensitive.pdf"))' .canary-scan/canary-scan-report.json

# Count by category
jq -s 'group_by(.category) | map({category: .[0].category, count: length})' \
  .canary-scan/canary-scan-report.json
```

### Other formats

```bash
# CSV for spreadsheet triage
canary-scan scan /mnt/datasource --format csv

# SARIF for GitHub Security tab or DefectDojo
canary-scan scan /mnt/datasource --format sarif

# All three formats at once
canary-scan scan /mnt/datasource --format all

# Re-render the report in a different format without re-scanning
canary-scan report --format sarif
```

### SIEM / pipeline integration

```bash
# Stream critical findings to stdout for piping
canary-scan scan /mnt/datasource --stdout --severity-threshold critical | \
  jq -c . | kafkacat -P -t canary-alerts
```

---

## 5. Filter findings

### Suppress false positives with an allowlist

Create a plain-text allowlist file (one domain/pattern per line):

```text
# Known-safe domains to suppress
w3.org
schemas.openxmlformats.org
adobe.com
*.microsoft.com
```

Or a JSON list:

```json
["w3.org", "adobe.com", "*.microsoft.com"]
```

Or a JSON dictionary for fine-grained control:

```json
{
  "domains": ["w3.org", "adobe.com"],
  "urls": ["http://known-safe.example.com/update.gif"],
  "files": ["/mnt/datasource/vendor-supplied-template.pdf"],
  "metadata": {
    "producer": ["Adobe PDF Library", "Microsoft Word"]
  }
}
```

Apply with:

```bash
canary-scan scan /mnt/datasource --allowlist allowlist.json
```

### Force-flag specific indicators with a denylist

```bash
canary-scan scan /mnt/datasource --denylist denylist.json
```

Denylist entries use the same file formats as allowlist entries.

---

## 6. Re-runs and audit trail

By default, `--resume` is active: any stage that completed successfully in a prior run (recorded in `canary-scan-state.json`) is skipped on re-run.

```bash
# Continue an interrupted scan
canary-scan scan /mnt/datasource

# Re-run all stages from scratch, appending a new audit entry
canary-scan scan /mnt/datasource --force

# Re-render the report with a stricter severity threshold (no re-scan)
canary-scan report --severity-threshold high

# Re-render the report with a different format
canary-scan report --format csv
```

The `canary-scan-state.json` file maintains an append-only `runs[]` array recording every run with timestamps, exit codes, stages executed, and CLI arguments — suitable for chain-of-custody documentation.

!!! warning "Concurrent runs"
    The output directory is flock-locked during a scan. A second `canary-scan` process targeting the same output directory exits with code **5**.

---

## Output directory layout

```
.canary-scan/
  canary-scan-inventory.json        # inventory stage
  canary-scan-metadata.json         # metadata stage
  canary-scan-remote-refs.json      # remote-refs stage
  canary-scan-embedded.json         # embedded stage
  canary-scan-embedded/             # extracted embedded objects
  canary-scan-stego.json            # stego stage
  canary-scan-unique-clusters.json  # uniqueness stage
  canary-scan-report.json           # final merged report (JSON)
  canary-scan-report.csv            # if --format csv|all
  canary-scan-report.sarif          # if --format sarif|all
  canary-scan-state.json            # run audit trail + flock state
  canary-scan.log                   # full subprocess invocation log
```

---

## Exit codes

| Code | Meaning | Remediation |
|---|---|---|
| 0 | Clean run | — |
| 2 | Missing required dependency | Run `canary-scan deps --fix-hints` |
| 3 | (Reserved) Writable mount detected | Warning is printed; execution continues |
| 4 | Partial run — one or more stages errored | Check `canary-scan.log`; re-run with `--resume` |
| 5 | Output directory locked by another run | Wait for the active run to complete |
