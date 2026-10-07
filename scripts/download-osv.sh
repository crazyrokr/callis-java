#!/usr/bin/env bash
# T61: download the OSV Maven snapshot and pin it (A14).
#
# Usage: bash scripts/download-osv.sh [DEST]   (default DEST: osv-maven)
#
# Writes the extracted records to DEST (one *.json per advisory) and a
# <DEST>.sha256 pin file next to the directory. The pin is the analyzer's
# SnapshotChecksum.sha256OfDirectory value — over all *.json directly
# under DEST, sorted by file name, concatenate name:sha256(file)\n and
# take the sha256 of the concatenation — so the analyzer's
# --osv-checksum "$(cut -d' ' -f1 <DEST>.sha256)" verifies the exact
# snapshot the report was computed against.

set -euo pipefail

URL="https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
DEST="${1:-osv-maven}"
DEST="${DEST%/}"
PIN="${DEST}.sha256"

snapshot_sha256() {
    # Mirrors org.reachability.analyzer.osv.SnapshotChecksum (same order,
    # same encoding). Empty input hashes as the sha256 of empty data. The
    # whole computation runs in one subshell so every sha256sum resolves
    # against DEST, not the caller's working directory.
    (
        cd "$DEST"
        ls -1 -- *.json | LC_ALL=C sort \
            | while IFS= read -r f; do
                printf '%s:%s\n' "$f" "$(sha256sum "$f" | cut -d' ' -f1)"
              done \
            | sha256sum | cut -d' ' -f1
    )
}

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

echo "downloading $URL ..."
curl -fL --retry 3 -o "$tmp" "$URL"

mkdir -p "$DEST"
unzip -oq "$tmp" -d "$DEST"

sha256="$(snapshot_sha256)"
printf '%s  %s\n' "$sha256" "$DEST" > "$PIN"

count="$(cd "$DEST" && ls -1 -- *.json | wc -l)"
echo "extracted $count record file(s) to $DEST"
echo "snapshot sha256: $sha256 (written to $PIN)"
echo "pin the analyzer with: --osv-checksum $sha256"
