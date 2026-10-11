# ADR 0017 — A16: Caching & parallelism deferred, benchmark-gated

- **Status:** accepted (2026-10-05); amended: M4 verification (2026-10-07)
- **Related:** ADR 0001 (index), ADR 0005 (fixture the baseline was measured on), ADR 0006 (call-graph policies)

## Decision

SootUp 3.0.1 caches are in-memory only (no call-graph serialization API) and
`GraphBasedCallGraph` is not thread-safe. Full-CG disk caching rejected for v1:
app classes change every commit, so the cache key almost always misses in CI.
JAR-level SHA-256 parse cache and snapshot-based parallel path-finding are M7
stretch items, implemented only if an M4 benchmark on a medium real project shows
parse/path work dominates.

## Amendments

- **2026-10-07 (M4 verification):** A16 baseline on the 49-class
  `fixtures/mini-app` (shadow JAR, Java 25.0.3-tem): RTA graph
  **27 nodes / 44 calls, build ≈ 99 ms**; full pipeline
  (SBOM + OSV + guard + view + entries + graph + verdicts) **≈ 382 ms**
  analysis, **≈ 0.5 s wall** (JVM startup dominates). The
  `examples/vulnerable-demo` < 60 s acceptance is measured in M6 when the
  demo is created; the M4 fixture pipeline already meets it by two orders
  of magnitude. (The fixture-growth half of the same M4 record lives in
  ADR 0005.)
