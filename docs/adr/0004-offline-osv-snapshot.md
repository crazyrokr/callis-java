# ADR 0004 — A3: Offline OSV via local directory + `download-osv.sh`

- **Status:** accepted (2026-10-05); amended: M6 verification (2026-10-07)
- **Related:** ADR 0001 (index), ADR 0015 (OSV snapshot pinning + fail-safe parsing)

## Decision

Air-gapped requirement. The GCS `Maven/all.zip` is ~10.3 MB (verified 2026-10-05,
daily refresh), so CI download is cheap; a corporate Nexus/Artifactory cache is an
ops option, not an app dependency. `--osv-dir` is the only contract (R7).

## Amendments

- **2026-10-07 (M6 verification):** snapshot download + pinning (T61).
  `scripts/download-osv.sh` fetches `Maven/all.zip` (`curl -fL --retry 3` →
  mktemp → `unzip -oq`) and writes `osv-maven.sha256` with the **same
  algorithm** as `SnapshotChecksum` (sha256 over `name:filesha256` lines,
  `LC_ALL=C`-sorted; the whole computation runs in one subshell so the
  `cd` applies to every per-file hash). Parity verified: shell pin ==
  analyzer-computed == `69a25c75…` over 7,168 records.
