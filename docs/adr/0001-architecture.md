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
`BytecodeCeilingSpec` regression fixture (its probe binaries are generated
at build time since M7a; see A12).

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

### A5 — RTA default, `--cha` flag, `--pointer-analysis` flag (SPARK)

RTA (`RapidTypeAnalysisAlgorithm`) prunes to the set reachable from entry points →
fewer false positives from dead code. SootUp 3.0.1's RTA is already
allocation-sensitive (a virtual call expands only to subtypes instantiated by a
`new` expression), so its remaining false-positive mode is a class that is
instantiated somewhere but never dispatched at a call site. CHA
(`ClassHierarchyAnalysisAlgorithm`) keeps everything the hierarchy could reach —
the least precise mode, a comparison tool rather than a gate. SPARK
(`org.soot-oss:sootup.spark`, behind `--pointer-analysis`, M7b) is the
object-sensitive pointer-analysis mode: its call graph grows on-the-fly from the
entry points and a call edge exists only when the incremental points-to analysis
justifies the dispatch, pruning that instantiated-but-never-dispatched class
(`PointerDemo2` fixture: RTA/CHA keep the edge, SPARK prunes it).

Deviation from the plan text: the plan said "Heros IFDS"; SootUp 3.0.1 ships
SPARK as the maintained implementation of exactly that capability
(`sootup.analysis.interprocedural` is the raw IFDS framework — no ready-made
Heros exists) → SPARK.

SootUp 3.0.1 API facts that shaped the implementation (empirical, verified
against the resolved jars and the v3.0.1 sources): under the default
`SparkOptions`, `Spark.getCallGraph()` returns the seed graph **unchanged**
(`solve()` only builds the PAGs), so an "RTA seed + refinement" recipe is a
no-op; refinement exists only in `onFlyCallGraph(true)` mode, where the Solver
discards any pre-built graph and grows a `GraphBasedCallGraph` from the entry
points. ⇒ the SPARK mode runs on-the-fly **without a seed** (an RTA seed
passed in that mode would be discarded anyway).

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

### A10 — Single Gradle project for v1, multi-module from M7a

v1 was a single Gradle project; split `core`/`cli` (and add Gradle/Maven
plugins) only when a library consumer appears — that split is the M7 trigger
for plugin work. **M7a (2026-10-07) realized the split:** root aggregator +
`core` (sbom/osv/analysis/report + the new `engine` package), `cli`
(picocli + shadow fat JAR), `tools:coveragetool`. `core:engine.AnalyzerEngine`
is the in-process seam the M7e plugins call — the whole M4/M5 pipeline plus
report generation behind `analyze(AnalysisRequest, output, formats, verbose,
DiagnosticSink)`, console I/O abstracted so the CLI and plugins surface the
same diagnostics with the same exit codes.

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
fixtures (`fixtures/bytecode/v69`, `fixtures/bytecode/v70`); since M7a they are
generated at build time (v69 compiled from its committed source; v70 = the
61-byte hand-crafted probe reproduced from a hex constant — no fixture
binary has been in the git history since the 2026-10-08 rewrite).
Note: SootUp 3.0.1's ASM
**does** parse fully valid v70 classes — the zero-classes contract holds only
for the deliberately unparseable probe body, which is why the probe stays
hand-crafted bytes rather than compiled output.

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
- **2026-10-06 (M3 verification):** SootUp `ArrayType.getBaseType()` unwraps
  **multi-dimensional** arrays to the innermost element (`String[][]` →
  `String`), so the `main(String[])` check needed an explicit
  `getDimension() == 1` — without it `main(String[][])` is accepted as a JVM
  entry point (false positive; the `BadMains` fixture pins all five trap
  overloads as non-entries).
- **2026-10-06 (M3 verification):** entry-point detection (A6/A13) as built:
  `main(String[])` of **app classes only** (library mains in jars are never
  entries); framework handler annotations read from bytecode
  (`org.springframework.web.bind.annotation.*`, `@Scheduled`, `@KafkaListener`,
  `@RabbitListener`); `doGet`/`doPost` of `@WebServlet` (javax/jakarta)
  classes or `HttpServlet`/`jakarta HttpServlet` subclasses; and the bounded
  callback list (A13: `javax/jakarta.servlet.Filter#doFilter`,
  `org.quartz.Job#execute`,
  `org.springframework.context.ApplicationListener#onApplicationEvent`,
  `javax/jakarta.jms.MessageListener#onMessage`) resolved through the
  interface/superclass chain (depth cap 16, duplicate-seen skip). Plain
  business interfaces are **never** callback sources (precision guard,
  pinned); `--callback-interfaces` extends the list and `--entry-points
  class#method` overrides auto-detection (malformed / unknown entries are
  warned, not fatal).
- **2026-10-06 (M3 verification):** the call graph is RTA by default (prunes
  to what the entry points reach — the plan's false-positive pin: a dead
  virtual call to a never-instantiated implementation is pruned under RTA
  but kept under `--cha`, both pinned), built via
  `sootup.callgraph.{RapidTypeAnalysis,ClassHierarchy}AnalysisAlgorithm` on
  the shared `JavaView` (A1). `--dry-run-graph` prints the detected entries
  (`-v`) and the graph node/call counts + build time (M3 acceptance); an
  app directory with **no detectable entry points is exit 3** (nothing to
  analyze is a broken invocation, not a clean pass). `OutOfMemoryError`
  during view/graph build becomes an `AnalysisException` with `-Xmx4g`
  guidance; classpath-file entries that are missing/unreadable become
  warnings (T34 skip-and-continue); a non-readable class directory fails the
  scan (`cannot scan` → exit 3).
- **2026-10-06 (M3 verification):** the `analysis` package lands at
  **BRANCH 136/138 = 0.9855** (gate ≥ 0.90); the two uncovered branches are
  the `OutOfMemoryError` catches (unreachable in the test JVM by design).
  The fixture `fixtures/mini-app` grows to 46 app classes (servlet
  superclass matrix, `@Marked` non-handler annotation, `BadMains` traps, a
  16-deep interface chain + diamond for the walk depth cap) with
  `StubSootClass`/`StubSootMethod`/`FakeView` test doubles for the
  `SootClass`/`SootMethod` annotation fallbacks (SootUp 3.0.1 exposes those
  as interfaces, so non-Java model objects are testable). The `examples/vulnerable-demo`
  < 60 s build-time acceptance is measured in M6, when the demo is created.

- **2026-10-07 (M4 verification):** verdict model (T41/T44). A candidate
  matches at **METHOD level** when its mapping names methods that resolve
  in the parsed view (reachability = the resolved signature is in the call
  graph); otherwise it falls back to **ARTIFACT level** (any class of the
  artifact's jar with a method in the graph — constructors excluded:
  instantiating the artifact is not use of a vulnerable method). States:
  `REACHABLE`, `UNREACHABLE`, `NO_CLASS_INFO`. **A14 `onClasspath`**:
  artifact present in the parsed view but nothing reachable → `UNREACHABLE`
  + console `NOTICE ... artifact present in classpath - possible reflection
  or dynamic dispatch risk`; artifact absent from the classpath entirely →
  `NO_CLASS_INFO` + `NOTICE ... artifact not on classpath - no class info`.
  Any `REACHABLE` ⇒ exit 1 with a `CRITICAL` line + the call path; all
  unreachable ⇒ exit 0; zero candidates short-circuits before the analysis
  (exit 0).
- **2026-10-07 (M4 verification):** the optional `--mappings
  vuln-mappings.json` (T42) is a strict object
  `{"VULN-ID": [{"class": "...", "method": "...", "descriptor": "(...)"?}]}`,
  validated at startup before any analysis (malformed ⇒ exit 2, unreadable
  ⇒ exit 2). `descriptor` is a source-style parameter list that narrows the
  match to one overload (matched against the sub-signature suffix). Mapping
  ids that match no candidate are warned, never fatal; an empty target list
  falls back to the artifact level. Artifact jars are indexed by file name
  (`name[-version]` stem → binary class names); a version-suffixed jar
  matching the SBOM version is preferred, with fallback to the union of all
  same-named jars; unreadable/corrupt jars warn and are skipped (T34
  skip-and-continue).
- **2026-10-07 (M4 verification):** path extraction (T43) is a multi-source
  BFS over the reachability-reduced graph — one shortest path per
  candidate, hops as `class#method`. Determinism: sources are sorted by the
  **user-visible `class#method` hop string**, not by
  `MethodSignature.toString()`: the latter renders
  `<demo.VulnCaller: void main(...)>`, where the `:` sorts after digits, so
  `VulnCaller2` would precede `VulnCaller` (pinned: two equal-distance
  callers yield exactly the lexicographic-first path, repeat-call
  identical; a closer caller beats a farther one).
- **2026-10-07 (M4 verification):** A16 baseline on the 49-class
  `fixtures/mini-app` (shadow JAR, Java 25.0.3-tem): RTA graph
  **27 nodes / 44 calls, build ≈ 99 ms**; full pipeline
  (SBOM + OSV + guard + view + entries + graph + verdicts) **≈ 382 ms**
  analysis, **≈ 0.5 s wall** (JVM startup dominates). The
  `examples/vulnerable-demo` < 60 s acceptance is measured in M6 when the
  demo is created; the M4 fixture pipeline already meets it by two orders
  of magnitude. `fixtures/mini-app` grew to 49 app classes (`VulnCaller`,
  `VulnCaller2`, `VulnService` for the positive chain and the lexicographic
  tie); new fixtures `bom-mini.json`, `osv-mini/VULN-POS.json`,
  `mappings/{valid,malformed,malformed-entry}.json`.
- **2026-10-07 (M4 verification):** the `analysis` package lands at
  **BRANCH 272/288 = 0.9444** (gate ≥ 0.90, up from 136/138 in M3). The
  remaining uncovered branches are defensive sub-branches unreachable in
  the test setup — null `Path.getFileName()` at the filesystem root,
  Jackson `NullNode`-vs-`null` distinctions, `&&`/`||` short-circuit
  sub-conditions — kept as guards in the same spirit as the M3
  `OutOfMemoryError` catches.
- **2026-10-07 (M5 verification):** report model (T51). `AnalysisReport` is
  run metadata (tool version, CG builder, entry-point count, CG
  node/call counts, duration, detected target bytecode major, OSV snapshot
  sha256, OSV parse-skip count) plus one entry per candidate: id, component
  **purl** (the SBOM purl verbatim, qualifiers included — e.g.
  `…log4j-core@2.14.1?type=jar`), `REACHABLE|UNREACHABLE` (the
  NO_CLASS_INFO state reports UNREACHABLE with onClasspath=false),
  onClasspath, `severity`, `affectedRange`, `path[]`. Severity (T51) comes
  from the OSV top-level `severity` array as `TYPE` or `TYPE: score`
  strings, falling back to `database_specific.severity` (e.g. `CRITICAL`);
  both parses are **lenient** — severity is metadata, malformed entries are
  skipped, never record-rejecting (contrast the strict ADR-0001 M2 core
  fields). `affectedRange` is the matcher's evidence joined
  (`range#0 (introduced=0, fixed=2.0)` / `versions`). `OsvRecord` gained a
  `severities` field and `VulnerabilityCandidate` gained `purl` +
  `severities` (one candidate per (record, component), so the record's
  severity flows to the candidate).
- **2026-10-07 (M5 verification):** writers (T52/T53). `JsonReportWriter`
  serializes via Jackson `ObjectNode` — key order is the model's
  declaration order (insertion order), so output is byte-stable; the
  committed golden `fixtures/reports/reachability-report.golden.json` is
  re-recorded from the writer's own output (Jackson 2.22
  `DefaultPrettyPrinter` renders arrays inline, `[ { … } ]`). Absent
  optional metadata (bytecode major, OSV sha256) serializes as JSON `null`.
  `JUnitXmlReportWriter` emits one `<testsuite name="reachability">` and
  one `<testcase name="&lt;id&gt; &lt;purl&gt;">` per candidate:
  REACHABLE ⇒ `<failure message="reachable">` with the call trace in the
  body; UNREACHABLE ⇒ pass with a `<skipped>` note (onClasspath ⇒
  "artifact present in classpath … possible reflection/dynamic dispatch
  risk", A14; otherwise ⇒ "artifact not on classpath — no class info").
  **The suite fails exactly when the pipeline must fail (exit 1)** —
  `failures` equals the reachable count, so CI badges stay honest. All five
  XML specials are escaped (pinned: `& < > " '` round-trip through a DOM
  parse). Golden `…golden.xml` committed; both writers at
  **LINE 87/87 = 1.0** (gate active from M5).
- **2026-10-07 (M5 verification):** console + CLI (T54). The M4
  CRITICAL/NOTICE lines are kept; a summary table (id, component, verdict,
  **path head** only) is added so the console never duplicates the full
  report. `--verbose` names the written files and the duration. Unknown
  `--format` token ⇒ exit 2; a non-writable report destination ⇒
  **exit 3** (parent directories are created when absent). `osv-mini/
  VULN-POS.json` gained a `severity` array so the pipeline report carries
  real severity end-to-end. Coverage: osv LINE 262/262 = 1.0,
  BRANCH 187/198 = 0.9444; analysis unchanged at 272/288 = 0.9444.
- **2026-10-07 (M6 verification):** snapshot download + pinning (T61).
  `scripts/download-osv.sh` fetches `Maven/all.zip` (`curl -fL --retry 3` →
  mktemp → `unzip -oq`) and writes `osv-maven.sha256` with the **same
  algorithm** as `SnapshotChecksum` (sha256 over `name:filesha256` lines,
  `LC_ALL=C`-sorted; the whole computation runs in one subshell so the
  `cd` applies to every per-file hash). Parity verified: shell pin ==
  analyzer-computed == `69a25c75…` over 7,168 records.
- **2026-10-07 (M6 verification):** living integration test (T65).
  `examples/vulnerable-demo` — Maven **on purpose** (the tool is Gradle; the
  demo proves cross-build-system analysis), CycloneDX 2.9.1 at package time,
  log4j 2.14.1 pinned, log4j-core used directly from `main()`. Vulnerable pin:
  **exit 1, 8 REACHABLE** (incl. log4shell `GHSA-jfh8-c2jp-5v3q` and 2026
  log4j-api/core records), 5–19-hop traces through real log4j internals
  (e.g. `LoggerContext#<clinit>` → … → `LoggerConfig#processLogEvent`), ~2.7 s
  wall on the full 7,168-record snapshot (A16 < 60 s). Fixed pin **2.25.5**
  (at or beyond every log4j fixed bound in the current snapshot: log4j-core
  max fixed 2.25.4, log4j-api `GHSA-qv9r-c865-cp47` fixed 2.25.5): **exit 0,
  zero candidates**.
- **2026-10-07 (M6 verification):** consumer CI templates (T62/T63). The GH
  workflow runs the analyzer with `continue-on-error` + a
  `steps.*.outcome == 'failure'` gate, so it **fails by design** on this
  repository (the committed demo pin is the red variant) while always
  uploading both reports; the Gradle target variant is documented inline
  (A7). The Jenkinsfile is declarative (`Build & SBOM` → `OSV cache` via
  `stash` with the pin verified on every build → `Reachability Analysis` →
  archive `reachability-report.*`); it fails naturally on exit 1. Groovy
  note recorded: named-argument calls inside a `$(…)` GString interpolation
  do not lex, so the cache-hit echo is a plain string with shell-level
  `\$()`.
- **2026-10-07 (M6 verification):** stale-report deletion. A run that ends
  before report generation (zero candidates, analysis failure) used to leave
  a previous run's `reachability-report.*` behind — the CLI now deletes
  existing report files at analysis start (warns, does not fail, when a
  delete is impossible). Regression: CliSpec pre-creates reports, runs a
  zero-candidate pipeline into the same base name, and asserts both are gone
  (exit 0).
- **2026-10-07 (M7a):** multi-module split + engine facade (A10).
  * Structure: root aggregator + `core`, `cli`, `tools:coveragetool`;
    per-module Checkstyle/JaCoCo/SpotBugs; the coverage gates re-target
    core's exec data (thresholds unchanged, all green). SootUp modules are
    declared `api` in core because SootUp types leak through public
    signatures (`SootUpSetup`, `CallGraphFactory.BuildResult`) — plain
    `implementation` broke the cli compile.
  * `engine.AnalyzerEngine.analyze(AnalysisRequest, output, formats,
    verbose, DiagnosticSink)` owns the full pipeline; the CLI shrinks to
    options → `AnalysisRequest` + the engine's exit code (dry-run modes
    stay CLI-only). Console output stayed byte-identical: the unchanged
    CliSpec is the net, and the rebuilt fat JAR replays the demo
    identically (2.14.1 → exit 1, 8 REACHABLE, JSON equal ignoring
    duration; 2.25.5 → exit 0).
  * Records with mutable components (`AnalysisRequest`) copy in a compact
    constructor (`List.copyOf`/`Map.copyOf`): SpotBugs 4.10.4 reports
    EI_EXPOSE_REP/EI_EXPOSE_REP2 for record accessors/constructors that
    expose raw collections — the same convention `VulnerabilityCandidate`
    already used (verified with a probe record against the pinned
    SpotBugs version).
  * Gradle 9.8.0 gotcha (empirical, bbb/aaa/ccc experiment): subprojects
    evaluate in **alphabetical** order, not `settings.gradle.kts` include
    order → cross-project source-set access at configuration time is
    unreliable in both directions. Cross-module test dependencies go
    through `java-test-fixtures` (core's TestPermissions consumed by the
    cli test) and task-level wiring (coveragetool's `test` depends on
    core's `test` and consumes the exec/classes dirs via system
    properties).
  * True test total is 358 (core 287 + cli 40 + coveragetool 31); the
    engine spec adds 9 (367). The older "327" figure had missed the
    separate `coverageGateTest` results directory (31 tests).
  * Fixture de-binary-ization: the then-committed fixture binaries (49
    mini-app classes, stublib.jar, 2 bytecode probes) are removed from
    the repo — and from the entire git history (2026-10-08 rewrite;
    the only tracked binary in any commit is now the Gradle wrapper
    jar); `core` build tasks regenerate them before any test
    (mini-app: compileFixtureLib → stublibJar (JarOutputStream) →
    compileFixtureApp against the full lib dir, as the M3 recipe did;
    v69 probe compiled, v70 probe reproduced byte-exact from the
    hand-crafted 61-byte probe's hex — a valid v70 class would parse
    under SootUp 3.0.1's ASM and break the zero-classes contract).
    Generated paths are gitignored; the M3 manual rebuild recipe is
    replaced by the tasks. Verified before the history rewrite:
    49/49 mini-app classes rebuild byte-identical under javac 25.0.3
    (stublib.jar identical modulo entry metadata); the generated v70
    is byte-identical to the then-committed M0 file.
  * Gradle 9.8.0 build-script gotchas hit while wiring the generators:
    cross-project task references from :cli must be live `matching{}`
    queries (:cli evaluates first, alphabetically — `named()` is strict
    at call time); `AbstractArchiveTask` lost its destination setter
    (and `ProjectFile`/`Directory.asFile` resolve oddly), so stublib.jar
    is written with a plain Task + JarOutputStream; `include("*.java")`
    does not match nested files (use `**/*.java`); and a generator
    writing into `src/test/resources` must be an explicit dependency of
    `processTestResources` (implicit-dependency validation).
- **2026-10-09 (M7b):** SPARK pointer-analysis mode (A5 amended in place).
  * Dependency: `org.soot-oss:sootup.spark` 3.0.1 (same pin as the rest of
    SootUp) as `implementation` in `core` — SPARK stays internal to
    `CallGraphFactory`, nothing leaks into the API.
  * `CallGraphFactory.build(view, entryPoints, boolean cha)` →
    `build(view, entryPoints, CallGraphPolicy policy)` (enum RTA/CHA/SPARK,
    new `engine/CallGraphPolicy`); the SPARK branch runs
    `Spark.builder().view(...).entryPoints(...).sparkOptions(SparkOptions
    .builder().onFlyCallGraph(true).build()).build()` → `solve()` →
    `getCallGraph()`. Two empirical discoveries reshaped the plan's recipe:
    (1) SootUp 3.0.1's RTA is already allocation-sensitive, so the
    plan's "RTA false positive at a pure allocation site" pin does not hold
    — the true RTA↔SPARK discriminator is an instantiated-but-never-dispatched
    class; (2) `defaultOptions() + callGraph(seed)` is a no-op refinement
    (`getCallGraph()` returns the seed unchanged; the Solver refines only in
    `onFlyCallGraph` mode, where it discards any seed) — hence OTF without a
    seed. Both recorded above in the amended A5.
  * CLI: `--pointer-analysis`, mutually exclusive with `--cha` (both → exit 2
    "mutually exclusive"); report metadata `callGraphBuilder` = `SPARK`;
    `--dry-run-graph` names the policy.
  * Fixtures: `demo.PIface`, `demo.SafeImpl`, `demo.DangerImpl`,
    `demo.PointerDemo` (allocation-only dispatch — already pruned by 3.0.1's
    RTA, pinned as such) and `demo.PointerDemo2` (the discriminator:
    `new DangerImpl()` by assignment, never dispatched — RTA/CHA keep the
    `danger` edge, SPARK prunes it while keeping the executed `DangerImpl#
    <init>` and the true-positive chain intact). Fixture app classes 49 →
    54; entry points 21 → 23 (pinned).
  * Tests written first, then implementation: `CallGraphFactorySpec` 8 → 15
    (the SPARK suite pins the subset property — SPARK nodes and (source,
    target) edge pairs are a strict subset of RTA's — plus the true
    negative, the preserved true positive, and independent multi-entry
    exploration); `CliSpec` 40 → 43; `AnalyzerEngineSpec` 9 → 10 (296 → 304); the
    `CallPathFinderSpec`/`ReachabilityCheckerSpec`/`EntryPointDetectorSpec` /
    `AnalysisContextSpec` call sites migrated to the policy enum. Suite
    total 378 (core 304 + cli 43 + coveragetool 31), all green.
  * E2E demo (log4j 2.14.1, 2026-10-09, Temurin 25.0.3, fat JAR): RTA and
    `--pointer-analysis` runs both exit 1 with 8/8 REACHABLE on the same
    ids; the SPARK graph is 316 nodes / 625 edges vs RTA's 1557 / 4923 and
    the wall time is 1.90 s vs 2.76 s (on-the-fly mode grows the graph only
    along justified calls); all 8 reported paths differ (different shortest
    routes in the subset graph — the SPARK routes are shorter) while every
    endpoint stays inside the log4j artifact: the artifact-level demo has
    no receiver-sensitive dispatch, so the verdicts are unchanged as the
    plan required.
  * Coverage gates unchanged and passing (new code lands under
    `analysis`/`engine`, already gated); SpotBugs/Checkstyle clean.
