# ADR 0009 — A8: Exit codes: 0 / 1 / 2 / 3

- **Status:** accepted (2026-10-05); amended: M5 verification (2026-10-07)
- **Related:** ADR 0001 (index), ADR 0010 (reports), ADR 0011 (plugins surface the same exit codes)

## Decision

`0` = no reachable vulns; `1` = ≥1 REACHABLE (fail the pipeline); `2` =
usage/config error; `3` = analysis/runtime failure. 2 vs 3 lets CI distinguish a
broken invocation from an analyzer crash. Wired through a single `CliResult`
enum — no scattered `System.exit`.

## Amendments

- **2026-10-07 (M5 verification):** `--format` handling (T54). Unknown
  `--format` token ⇒ exit 2; a non-writable report destination ⇒
  **exit 3** (parent directories are created when absent). (The console
  summary table / `--verbose` half of the same M5 record lives in ADR 0010;
  its coverage numbers in ADR 0018.)
