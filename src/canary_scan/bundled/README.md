# Third-Party Licenses & Vendored Scripts

This directory contains third-party software bundled with `canary-scan` for offline / air-gapped utility.

## Didier Stevens Suite

The following scripts by Didier Stevens are bundled under `canary_scan/bundled/`
for air-gap-friendly operation. They are distributed under their original
license terms (BSD 2-Clause / public-domain-style as published by the author).
See each script's in-file header for the definitive license text.

Pin provenance is recorded in `canary_scan/bundled/VERSIONS.txt`.

| Script | Version | Source | Commit SHA | Fetch date |
|---|---|---|---|---|
| pdfid.py | (see VERSIONS.txt) | https://github.com/Didier-Stevens/Beta | (see VERSIONS.txt) | (see VERSIONS.txt) |
| pdf-parser.py | (see VERSIONS.txt) | https://github.com/Didier-Stevens/Beta | (see VERSIONS.txt) | (see VERSIONS.txt) |
| rtfdump.py | (see VERSIONS.txt) | https://github.com/Didier-Stevens/Beta | (see VERSIONS.txt) | (see VERSIONS.txt) |

### Upstream License

Source: https://github.com/Didier-Stevens/Beta/blob/master/LICENSE

```
Copyright (c) 2024 Didier Stevens

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

---

## Updating Vendored Scripts

To fetch or update these scripts from upstream, run the `fetch.sh` script located in this directory:

```bash
# Run from repository root
bash src/canary_scan/bundled/fetch.sh
```

### How the Fetch Script Works
The `fetch.sh` script handles the following tasks to maintain our local copies of these third-party scripts:
1. **Upstream Cloning**: Clones the latest upstream Beta suite repository into a temporary directory.
2. **File Mapping & Renaming**: Extracts the required scripts and renames any files with hyphens (e.g., `pdf-parser.py`) to underscores (e.g., `pdf_parser.py`) so they are valid Python module names for local import.
3. **Metadata Headers**: Prepends a provenance header to each file, recording the source URL, exact Git commit hash, version, fetch date, and a pointer to this `README.md` file for licensing info.
4. **VERSIONS.txt Generation**: Automatically regenerates the `VERSIONS.txt` file in this directory to serve as the single source of truth for the currently pinned hashes.

