#!/usr/bin/env bash
# Fetch vendored third-party assets — Didier Stevens scripts for bundled PDF/RTF analysis.
set -euo pipefail

DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Didier Stevens Suite repository — source of pdfid.py, pdf-parser.py, rtfdump.py
# https://github.com/DidierStevens/DidierStevensSuite
BETA_REPO="https://github.com/DidierStevens/DidierStevensSuite.git"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Cloning Didier Stevens Suite..."
git clone --depth 1 "${BETA_REPO}" "${TMP_DIR}/beta"

# Scripts to fetch: source filename → bundled filename (hyphens → underscores for valid module names)
declare -A SCRIPT_MAP=(
    ["pdfid.py"]="pdfid.py"
    ["pdf-parser.py"]="pdf_parser.py"
    ["rtfdump.py"]="rtfdump.py"
)
COMMIT="$(cd "${TMP_DIR}/beta" && git rev-parse HEAD)"
DATE="$(date -u +%Y-%m-%d)"

for src_name in "${!SCRIPT_MAP[@]}"; do
    dest_name="${SCRIPT_MAP[$src_name]}"
    SRC="${TMP_DIR}/beta/${src_name}"
    if [[ -f "${SRC}" ]]; then
        # Add provenance header
        VERSION=$(grep -oP 'version.*?(\d+\.\d+\.\d+)' "${SRC}" | head -1 | grep -oP '\d+\.\d+\.\d+' || echo "unknown")
        {
            echo "# canary-scan bundled: ${src_name} (bundled as ${dest_name})"
            echo "# Source: ${BETA_REPO}"
            echo "# Commit: ${COMMIT}"
            echo "# Version: ${VERSION}"
            echo "# Fetch date: ${DATE}"
            echo "# License: BSD 2-Clause (see README.md)"
            echo ""
            cat "${SRC}"
        } > "${DEST}/${dest_name}"
        echo "  Vendored ${src_name} → ${dest_name} (version ${VERSION}, commit ${COMMIT:0:12})"
    else
        echo "  WARNING: ${src_name} not found in upstream repo" >&2
    fi
done

# Write VERSIONS.txt
cat > "${DEST}/VERSIONS.txt" << EOF
# Bundled Third-Party Scripts — Version Provenance
# canary-scan bundles the following Didier Stevens scripts.

| Script (source)  | Bundled as     | Source | Commit | Version | Fetch date |
|------------------|----------------|--------|--------|---------|------------|
| pdfid.py         | pdfid.py       | ${BETA_REPO} | ${COMMIT} | see file header | ${DATE} |
| pdf-parser.py    | pdf_parser.py  | ${BETA_REPO} | ${COMMIT} | see file header | ${DATE} |
| rtfdump.py       | rtfdump.py     | ${BETA_REPO} | ${COMMIT} | see file header | ${DATE} |

## Note
These are verbatim copies from the Didier Stevens Suite repository, with a provenance
header prepended. File names with hyphens are renamed to underscores for valid Python
module imports. They are licensed under BSD 2-Clause. See README.md for details.
EOF

echo "Done. VERSIONS.txt updated."
