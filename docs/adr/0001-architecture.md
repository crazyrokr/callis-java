# ADR 0001 — Architecture: Dependency Vulnerability Reachability Analyzer

- **Status:** accepted (2026-10-05)
- **Scope:** single shared record of all architectural decisions for this project.
  Per project convention, later changes **amend this file in place** — no per-change ADRs.
  Each amendment is appended to the [Amendments](#amendments) section.

## Context

The tool answers one question in CI: *"Is this vulnerability in the SBOM actually
reachable from application code?"* Pipeline: CycloneDX SBOM + local OSV database →
candidate vulnerabilities → SootUp call graph (entry points → app bytecode + library
jars) → REACHABLE / UNREACHABLE verdicts with call traces → JSON + JUnit XML reports.
Exit code 1 on any reachable vulnerability, 0 otherwise.

**Capability boundary (drives A4):** OSV Maven records carry package-level
`affected`/`ranges` data only — 0 of the 7,163 records in the current dump carry
class/method signatures (verified 2026-10-05). Reachability is therefore
artifact-level by default, with an optional `vuln-mappings.json` escape hatch for
critical CVEs.

**Bytecode support:** SootUp 3.0.1 (ASM 9.10.1) under a Java 25 runtime parses
class files up to major version 69 (Java 25), verified 2026-10-05. For unsupported
versions SootUp **silently** returns zero classes (verified: v69 under 2.0.0,
hand-crafted v70 under 3.0.1) — hence the A12 startup guard and the
`BytecodeCeilingSpec` regression fixture committed in M0.

## Decisions

### A1 — SootUp 3.0.1 over classic Soot / ASM-only

Modern API, Jimple IR, maintained; CHA + RTA call graphs out of the box.
`org.soot-oss` 3.0.1 modules are published on Maven Central (verified 2026-10-05 on
repo1.maven.org; the Solr search index lags and still shows 2.0.0). Parses
≤ Java 25 bytecode. All SootUp types are confined to `analysis/SootUpSetup.java`
so an upgrade is a one-file diff (R4).

### A2 — Fat-JAR via Shadow; GraalVM native deferred to M7

Instant-start CI is nice-to-have, not v1. SootUp's reflective use may need
native-image reflect config. If native is ever built, `org.graalvm.buildtools.native`
is the first-class path.

### A3 — Offline OSV via local directory + `download-osv.sh`

Air-gapped requirement. The GCS `Maven/all.zip` is ~10.3 MB (verified 2026-10-05,
daily refresh), so CI download is cheap; a corporate Nexus/Artifactory cache is an
ops option, not an app dependency. `--osv-dir` is the only contract (R7).

### A4 — Artifact-level reachability default; class/method-level via mapping file

OSV has no method data for Maven (capability boundary above). The default verdict
must not overpromise precision; `vuln-mappings.json` (vuln id → classes/methods)
gives the escape hatch. Documented as the #1 precision limitation (R1) in the README.

### A5 — RTA default, CHA flag `--cha`

RTA (`RapidTypeAnalysisAlgorithm`) prunes to the set reachable from entry points →
fewer false positives from dead code; CHA (`ClassHierarchyAnalysisAlgorithm`) is the
cheaper fallback. Pointer-analysis (Heros IFDS) precision is M7 stretch.

### A6 — Entry points: `main()` + annotation-driven + `--entry-points` override

`main(String[])` in **app classes only** (never library mains), plus bytecode-level
annotation scan for the frameworks in the spec: Spring controllers/handlers,
`@Scheduled`, JMS/Kafka/Rabbit listeners, `@WebServlet`/`doGet`/`doPost`, Quartz
`execute()`. Annotations are read from bytecode — no framework classpath needed.
An explicit `--entry-points class#method` list wins over auto-detection.

### A7 — Classpath scope = resolved dependency set (not `~/.m2/repository`)

For a Maven target: `mvn dependency:build-classpath -Dmdep.outputFile=cp.txt`;
for Gradle: a small custom task writing `cp.txt`. These commands run in the
*analyzed* project only. A GBs-sized, jar-irrelevant `~/.m2/repository` classpath
would slow the call graph down and is a precision hazard (R2).

### A8 — Exit codes: 0 / 1 / 2 / 3

`0` = no reachable vulns; `1` = ≥1 REACHABLE (fail the pipeline); `2` =
usage/config error; `3` = analysis/runtime failure. 2 vs 3 lets CI distinguish a
broken invocation from an analyzer crash. Wired through a single `CliResult`
enum — no scattered `System.exit`.

### A9 — Reports: JSON + JUnit XML

Per plan Phase 5. One `<testcase>` per vulnerability; REACHABLE ⇒ `<failure>`
with the call trace, UNREACHABLE ⇒ pass (badges fail exactly when the pipeline
must fail).

### A10 — Single Gradle project for v1

Split `core`/`cli` (and add Gradle/Maven plugins) only when a library consumer
appears — that split is the M7 trigger for plugin work.

### A11 — Spock (Groovy 4) as the test framework

Spock's `given:/when:/then:` is the mandated test structure as a language
construct; built-in assertions replace AssertJ (one assertion style across the
codebase); `where:` data tables make the M2 edge-case matrix one table per case
family; `Mock()`/`Stub()` are built-in (no Mockito). Production code stays 100%
Java; Groovy lives only under `src/test/groovy`.

### A12 — Java 25 LTS runtime; target-bytecode ceiling = Java 25

Verified 2026-10-05: Gradle 9.x supports Java 25 (≥ 9.1.0); Spock + Groovy 4.0.32
pass under 25; SootUp 3.0.1 runs under 25 and parses v69 class files. SootUp
**silently returns an empty class list** for bytecode versions it does not handle
(verified: v69 under 2.0.0; hand-crafted v70 under 3.0.1) — without a guard, a
target built with newer bytecode would pass with zero findings (false negative).
M3 keeps a startup guard: probe max class-file major version + zero-classes-from-
non-empty-directory check → **exit 3** beyond the supported ceiling. Regression
fixtures (`fixtures/bytecode/v69`, `fixtures/bytecode/v70`) committed in M0.

### A13 — Bounded callback-interface entry points

Enterprise code reaches vulnerable code via framework callbacks (Servlet `Filter`,
Quartz `Job`, Spring `ApplicationListener`, JMS listeners) that no annotation scan
catches. App classes implementing a curated, user-extensible list
(`--callback-interfaces`) become entry points; `JavaSootClass.getInterfaces()`
verified in SootUp 3.0.1. The "all interface implementations" variant is rejected:
it would admit every business interface, inflating entry points and collapsing RTA
precision (more false positives for a security gate).

### A14 — OSV snapshot pinning + fail-safe parsing + classpath NOTICE

TLS covers transit integrity; the enterprise need is reproducibility:
`download-osv.sh` writes an `osv-maven.sha256` pin, the analyzer records the sha256
in report metadata, optional `--osv-checksum` verifies. Robustness: malformed
records skipped with a count; **zero valid records → exit 3**; `withdrawn`
records (113 in the current dump) are never indexed. The report carries
`onClasspath` + a reflection/dynamic-dispatch NOTICE for UNREACHABLE-but-present
artifacts — closes the "quick win" without any method-data dependency.

### A15 — SBOM-format agnosticism via `SbomParser`

CycloneDX now (interface + auto-detect from `bomFormat` vs `spdxVersion`);
SPDX **JSON** in M7; SPDX XML excluded from v1. Enterprises split between the two
formats; the interface makes each new format one class.

### A16 — Caching & parallelism deferred, benchmark-gated

SootUp 3.0.1 caches are in-memory only (no call-graph serialization API) and
`GraphBasedCallGraph` is not thread-safe. Full-CG disk caching rejected for v1:
app classes change every commit, so the cache key almost always misses in CI.
JAR-level SHA-256 parse cache and snapshot-based parallel path-finding are M7
stretch items, implemented only if an M4 benchmark on a medium real project shows
parse/path work dominates.

## Corrections to plan.md (recorded for traceability)

- **SootUp 3.0.1** is published on Maven Central (verified on repo1.maven.org
  2026-10-05; the Solr search index lags and still reports 2.0.0). Supersedes any
  "wait for 3.x" caveat; raises the target-bytecode ceiling to Java 25 (A12).
- Build system: **Gradle 9.8.0 + Shadow** (not Maven/shade). All other decisions
  (SootUp, Jackson, picocli, offline OSV) unaffected; `maven-artifact` is a
  *library* dependency (`ComparableVersion`), not a build coupling.
- CycloneDX plugin **2.9.1**, not 2.8.0.
- `--classpath=~/.m2/repository` replaced by resolved classpath file (A7/R2).
- OSV all.zip is ~10 MB and daily-refreshed — direct CI download is viable;
  corporate cache optional.
- plan.md step 4.1 "extract affected class and method signatures from the database
  records" is not generally possible for Maven — replaced by A4.

## Amendments

- **2026-10-05 (M0 verification):** plan pin `Shadow 9.0.0-beta12` → **Shadow
  9.6.1** (9.0.0 GA and later stable 9.x releases exist on Central; T05 asked to
  re-check GA availability — done, latest stable preferred).
- **2026-10-05 (M0 verification):** plan pin `Spock 2.3-groovy-4.0` → **Spock
  2.4-groovy-4.0** (2.4 GA released; plan said "re-check at M0" — done). Groovy
  stays on the 4.0 line (4.0.32) per A11.
- **2026-10-05 (M0 verification):** other pins resolved — Jackson 2.22.3,
  picocli 4.7.7, maven-artifact 3.9.16, Checkstyle 10.4, JaCoCo 0.8.15, Gradle
  wrapper 9.8.0, runtime JDK 25.0.3 Temurin. All recorded in
  `gradle/libs.versions.toml` (single source of truth).
- **2026-10-05 (M0 verification):** the `com.diffplug.spotbugs` Gradle plugin is
  no longer published (absent from the plugin portal and Central in this
  timeline). Static analysis runs the current SpotBugs tool
  `com.github.spotbugs:spotbugs` **4.10.4** (chosen over 4.9.x because its ASM
  9.10.1 parses Java 25 class files) via a `spotbugsMain` `JavaExec` task with
  `-exitcode` so findings fail the build (verified with a planted
  `NP_ALWAYS_NULL` bug). Wired into `check`.
- **2026-10-05 (M0 verification):** SootUp **3.0.1 repackaged its API** —
  `org.sootup.*` is gone; core lives under `sootup.core.*` (e.g.
  `sootup.core.model.SootClass`, `sootup.core.types.ClassType`), the Java view
  under `sootup.java.core.views.JavaView` (constructor takes
  `AnalysisInputLocation` directly; `getClasses()` returns a `Stream`), the
  classpath location under
  `sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation`,
  and the algorithms under `sootup.callgraph` (`RapidTypeAnalysisAlgorithm` /
  `ClassHierarchyAnalysisAlgorithm`, `initialize(List<MethodSignature>)`).
  All M3 code targets this 3.x surface.
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
- **2026-10-06 (M2 verification):** OSV record parsing is **strict** — a
  record whose shape deviates from the OSV schema (non-object root, missing /
  non-text id, affected not a non-empty array, entry without a package name,
  range without an events array, event without exactly one of
  introduced/fixed/last_affected, non-text event version) throws
  `OsvFormatException`, which the repository converts to a warn + skip +
  count (T21b). Two invariants verified against the current dump: 0 of 7,163
  records are malformed, and 113 are `withdrawn` — withdrawn records are
  **never indexed** (counted separately, `indexedRecordCount =
  validRecordCount − withdrawnCount`).
- **2026-10-06 (M2 verification):** **name-key indexing** (refines A14): every
  affected entry is indexed under every name form of its package — the raw
  `group:artifact` name and its purl form `group/artifact` (5,471 of 5,674
  entries in the dump are `group:artifact`, 203 plain). A component purl
  queries under its `group:name` qualified name and its `group/name` form; a
  purl **without** a namespace queries its plain name only, so it never
  matches a group-qualified record of the same artifact name (false-positive
  guard, tested).
- **2026-10-06 (M2 verification):** **version-range semantics** (pure engine
  `VersionRangeMatcher`, Maven `ComparableVersion` ordering): `introduced`
  inclusive, `fixed` exclusive, `last_affected` inclusive; ranges OR; a range
  without events matches nothing (a security gate must not guess); the
  explicit `versions` list is exact string membership. A version **equal to
  `fixed` is not affected** (plan false-positive guard, tested: log4j-core
  2.15.0 → no candidate, 2.14.1 → candidate). The
  `database_specific.last_known_affected_version_range` hint is normalized
  only when the entry has no `fixed` event anywhere: `<= N` → inclusive
  `last_affected N`, `< N` → exclusive `fixed N` (the dump uses only those
  two shapes — 2,394 and 172 entries); an unparseable hint leaves the record
  unchanged.
- **2026-10-06 (M2 verification):** the **snapshot checksum** (A14) is the
  sha256 over the sorted `name + ":" + hexSha256(file) + "\n"` concatenation
  of all `*.json` files in the directory (order-independent, stable across
  re-extraction); `--osv-checksum <sha256>` verifies it and `--dry-run-match`
  prints the candidate table without bytecode analysis. A non-empty OSV
  directory yielding **zero valid records is the fail-safe** the CLI maps to
  exit 3 (A14/A8).
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
