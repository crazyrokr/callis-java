# ADR 0013 — A12: Java 25 LTS runtime; target-bytecode ceiling = Java 25

- **Status:** accepted (2026-10-05); amended: M3 verification (2026-10-06)
- **Related:** ADR 0001 (index), ADR 0002 (SootUp backend), ADR 0011 (fixture probes generated at build time since M7a)

## Context

**Bytecode support:** SootUp 3.0.1 (ASM 9.10.1) under a Java 25 runtime parses
class files up to major version 69 (Java 25), verified 2026-10-05. For unsupported
versions SootUp **silently** returns zero classes (verified: v69 under 2.0.0,
hand-crafted v70 under 3.0.1) — hence the A12 startup guard and the
`BytecodeCeilingSpec` regression fixture (its probe binaries are generated
at build time since M7a; see A12).

## Decision

Verified 2026-10-05: Gradle 9.x supports Java 25 (≥ 9.1.0); Spock + Groovy 4.0.32
pass under 25; SootUp 3.0.1 runs under 25 and parses v69 class files. SootUp
**silently returns an empty class list** for bytecode versions it does not handle
(verified: v69 under 2.0.0; hand-crafted v70 under 3.0.1) — without a guard, a
target built with newer bytecode would pass with zero findings (false negative).
M3 keeps a startup guard: probe max class-file major version + zero-classes-from-
non-empty-directory check → **exit 3** beyond the supported ceiling. Regression
fixtures (`fixtures/bytecode/v69`, `fixtures/bytecode/v70`); since M7a they are
generated at build time (v69 compiled from its committed source; v70 = the
61-byte hand-crafted probe reproduced from a hex constant — no fixture
binary has been in the git history since the 2026-10-08 rewrite).
Note: SootUp 3.0.1's ASM
**does** parse fully valid v70 classes — the zero-classes contract holds only
for the deliberately unparseable probe body, which is why the probe stays
hand-crafted bytes rather than compiled output.

## Amendments

- **2026-10-06 (M3 verification):** the A12 guard runs **twice**: before the
  view, `BytecodeVersionGuard.requireSupported` fails the run when any app
  class file is above major 69 (naming the offenders, the detected major, and
  the `--release` fix); before the zero-classes check, `SootUpSetup` fails
  loudly when a **non-empty** app class directory parses to zero classes —
  both `AnalysisException` → exit 3 (A8), because SootUp 3.0.1 otherwise
  returns an empty view for (a) bytecode beyond the ceiling and (b) corrupt
  class files (both silently return `[]`, verified by probe).

- **2026-10-06 (M3 verification):** SootUp 3.0.1 has a **second silent-zero
  path**: it drops `.class` files whose declared package does not match their
  path under the classpath entry (e.g. `demo/Main.class` at a directory's top
  level parses to nothing; `demo/Main.class` under `demo/` loads — verified by
  probe 2026-10-06). The zero-classes check above catches the all-or-nothing
  case; a partially mismatched directory would pass it, which is why the
  fixture layout (and the `--app-classes` contract) keeps package = path.
