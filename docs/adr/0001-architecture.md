# ADR 0001 — Architecture overview and ADR index

- **Status:** accepted (2026-10-05); **split 2026-10-10** into per-decision ADRs.
- **Convention:** this file was the single shared record of all architectural
  decisions (later changes amended it in place). On 2026-10-10 it was split:
  one ADR per decision (0002–0017, carrying the stable `A1`–`A16` labels
  referenced from README and code) plus two operational ADRs (0018–0019).
  **Future changes amend the specific decision ADR** — no single shared file.
  This index keeps the context, the plan corrections, the M0 version pins,
  and the milestone records that do not belong to a single decision.

## Context

The tool answers one question in CI: *"Is this vulnerability in the SBOM actually
reachable from application code?"* Pipeline: CycloneDX SBOM + local OSV database →
candidate vulnerabilities → SootUp call graph (entry points → app bytecode + library
jars) → REACHABLE / UNREACHABLE verdicts with call traces → JSON + JUnit XML reports.
Exit code 1 on any reachable vulnerability, 0 otherwise.

- **Capability boundary** (OSV Maven records carry package-level data only,
  so reachability is artifact-level by default): ADR 0005 (A4).
- **Bytecode support** (SootUp 3.0.1 parses up to class-file major 69 and
  silently returns zero classes beyond it — the A12 startup guard): ADR 0013 (A12).

## Index

| ADR | Decision | Title |
|---|---|---|
| [0002](0002-sootup-callgraph-backend.md) | A1 | SootUp 3.0.1 over classic Soot / ASM-only |
| [0003](0003-packaging-fatjar-native-image.md) | A2 | Fat-JAR via Shadow; GraalVM native-image from M7d |
| [0004](0004-offline-osv-snapshot.md) | A3 | Offline OSV via local directory + `download-osv.sh` |
| [0005](0005-artifact-level-reachability-mappings.md) | A4 | Artifact-level reachability default; class/method-level via mapping file |
| [0006](0006-call-graph-policies-rta-cha-spark.md) | A5 | RTA default, `--cha` flag, `--pointer-analysis` flag (SPARK) |
| [0007](0007-entry-point-detection.md) | A6 | Entry points: `main()` + annotation-driven + `--entry-points` override |
| [0008](0008-resolved-classpath-scope.md) | A7 | Classpath scope = resolved dependency set (not `~/.m2/repository`) |
| [0009](0009-exit-codes.md) | A8 | Exit codes: 0 / 1 / 2 / 3 |
| [0010](0010-reports-json-junit-sarif.md) | A9 | Reports: JSON + JUnit XML + SARIF 2.1.0 |
| [0011](0011-build-modules-gradle-maven-plugins.md) | A10 | Single Gradle project for v1, multi-module from M7a; Gradle + Maven plugins |
| [0012](0012-spock-test-framework.md) | A11 | Spock (Groovy 4) as the test framework |
| [0013](0013-java25-runtime-bytecode-ceiling.md) | A12 | Java 25 LTS runtime; target-bytecode ceiling = Java 25 |
| [0014](0014-bounded-callback-interfaces.md) | A13 | Bounded callback-interface entry points |
| [0015](0015-osv-snapshot-pinning-fail-safe-parsing.md) | A14 | OSV snapshot pinning + fail-safe parsing + classpath NOTICE |
| [0016](0016-sbom-format-agnosticism.md) | A15 | SBOM-format agnosticism via `SbomParser` |
| [0017](0017-caching-parallelism-deferred.md) | A16 | Caching & parallelism deferred, benchmark-gated |
| [0018](0018-coverage-gate-tooling.md) | — | Coverage gate tooling (`tools:coveragetool`, M1) |
| [0019](0019-renovate-configuration.md) | — | Renovate configuration (automatic dependency-update PRs) |

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

## Version pins and static-analysis tooling (M0)

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

(The M0 Shadow 9.6.1 and Spock 2.4 pins live with their decisions in
ADR 0003 and ADR 0012; the SootUp 3.x API-repackaging record lives in ADR 0002.)

## Milestone records (no single owning decision)

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
  zero candidates**. The workflow verifies the vulnerable pin against the
  committed `expected-reachable.txt` (the 8 ids, one per line): it passes
  on 2.14.1 and fails on 2.25.5 (2026-10-11).

- **2026-10-07 (M6 verification):** consumer CI templates (T62/T63). The GH
  workflow captures the analyzer's exit code, always uploads the reports,
  then verifies them: **on this repository it passes by design** (the
  committed demo pin is the red variant — vulnerabilities are expected):
  every id in `examples/vulnerable-demo/expected-reachable.txt` must be
  reported REACHABLE and all three formats must agree on the count; with
  no expected list (consumer repository) the gate semantics hold (fail
  when a vulnerability is reachable, pass on a clean run). (2026-10-11:
  the original `continue-on-error` + `steps.*.outcome == 'failure'` gate
  treated the expected exit 1 as a failure, so the verify step above
  replaced it.) The Gradle target variant is documented inline (A7). The Jenkinsfile is declarative (`Build & SBOM` → `OSV cache` via
  `stash` with the pin verified on every build → `Reachability Analysis` →
  archive `reachability-report.*`); it fails naturally on exit 1. Groovy
  note recorded: named-argument calls inside a `$(…)` GString interpolation
  do not lex, so the cache-hit echo is a plain string with shell-level
  `\$()`.
