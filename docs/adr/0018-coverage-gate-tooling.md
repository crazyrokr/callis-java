# ADR 0018 — Coverage gate tooling (`tools:coveragetool`, M1)

- **Status:** accepted (2026-10-06, M1); amended: M2, M3, M4, M5 verification (2026-10-06 … 2026-10-07)
- **Related:** ADR 0001 (index), ADR 0011 (`tools:coveragetool` module split), ADR 0010 (report writers LINE 87/87), ADR 0007 (M3 fixture record)

## Context

The plan's JaCoCo coverage gates (section 6: sbom/osv/report 100% line,
analysis ≥ 90% branch) could not be enforced by Gradle's built-in task —
see the M1 record below.

## Decision

`./gradlew check` runs a `coverageGate` `JavaExec` task executing
`org.reachability.coveragetool.CoverageGate` (module `tools:coveragetool`,
split in M7a — ADR 0011) instead of
`jacocoTestCoverageVerification`; the `jacoco` plugin stays applied for the
test agent and `jacocoTestReport`. Per-milestone coverage numbers are
recorded under Amendments.

## Amendments

- **2026-10-06 (M1 verification):** the plan's JaCoCo coverage gates are
  enforced by a **`coverageGate` `JavaExec` task** running
  `org.reachability.coveragetool.CoverageGate` (source set `coveragetool`,
  compiled against `org.jacoco:org.jacoco.core`), **not** by the
  `jacocoTestCoverageVerification` task. In Gradle 9.8 that task's ant worker
  (`AntJacocoCheck` + `org.jacoco.ant.ReportTask`) evaluates the execution
  data as empty — every package ratio comes out `0` regardless of the exec
  file wired in (verified: the same exec + class files analyzed directly via
  the core `Analyzer` API yield the correct ratios, e.g. sbom 145/151, while
  the Gradle worker reports 0 with 8 of 9 classes). Its rule evaluation is
  therefore untrustworthy. `CoverageGate` performs the identical
  ExecFileLoader → Analyzer → per-package LINE/BRANCH evaluation, prints a
  report, and exits 1 on any violation (verified with a planted dead
  statement: 151/152 → build fails). Gates per plan section 6: sbom/osv/report
  100% line, analysis ≥ 90% branch; packages without main classes yet are
  skipped. `CoverageGateSpec` (run in the separate `coverageGateTest` task
  after `test`, since the agent writes the exec file on test-JVM exit) covers
  the tool, including the false-positive guard "no data ≠ passing". The
  `jacoco` plugin stays applied for the test agent and `jacocoTestReport`.

- **2026-10-06 (M2 verification):** `CoverageGate` gained `--exclude <class>`:
  a class the JaCoCo agent does not instrument (or whose lines cannot be
  covered — e.g. `SnapshotChecksum`'s `NoSuchAlgorithmException` catch,
  unreachable because SHA-256 is a mandated JCA algorithm) is dropped from
  the analyzed class files, i.e. from **both** numerator and denominator.
  The exclusion must happen in the gate, where the class files are read:
  agent-level `excludes` only suppresses execution data, so the gate's
  `Analyzer` still sees the class file and counts its lines as uncovered
  (verified: 256/258 → 239/239 after the fix). `SnapshotChecksumSpec` pins
  the algorithm instead.

- **2026-10-06 (M3 verification):** the `analysis` package lands at
  **BRANCH 136/138 = 0.9855** (gate ≥ 0.90); the two uncovered branches are
  the `OutOfMemoryError` catches (unreachable in the test JVM by design).
  (The fixture-growth half of the same M3 record lives in ADR 0007.)

- **2026-10-07 (M4 verification):** the `analysis` package lands at
  **BRANCH 272/288 = 0.9444** (gate ≥ 0.90, up from 136/138 in M3). The
  remaining uncovered branches are defensive sub-branches unreachable in
  the test setup — null `Path.getFileName()` at the filesystem root,
  Jackson `NullNode`-vs-`null` distinctions, `&&`/`||` short-circuit
  sub-conditions — kept as guards in the same spirit as the M3
  `OutOfMemoryError` catches.

- **2026-10-07 (M5 verification):** coverage: osv LINE 262/262 = 1.0,
  BRANCH 187/198 = 0.9444; analysis unchanged at 272/288 = 0.9444.
  (Both report writers landed at LINE 87/87 = 1.0 — recorded in ADR 0010's
  M5 writers entry; the M5 console half of the same record lives in
  ADR 0010, its exit-code half in ADR 0009.)
