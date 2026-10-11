# reachability-analyzer

Answers one question in CI: **is this vulnerability in the SBOM actually
reachable from application code?**

Pipeline: `CycloneDX / SPDX 2.x SBOM` + `local OSV database` → candidate
vulnerabilities → `SootUp` call graph (entry points → app bytecode + resolved
library jars) → REACHABLE / UNREACHABLE verdicts with call traces → JSON +
JUnit XML + SARIF reports.
Exit code `1` on any reachable vulnerability (fail the pipeline), `0` otherwise
(`2` = usage error, `3` = analysis failure).

Status: v1 complete (M0–M6 of `implementation-plan.md`); M7 (stretch) in
progress — M7a done (multi-module split + engine facade), M7b done
(`--pointer-analysis` SPARK pointer-analysis mode), M7c done (SARIF findings
output + SPDX 2.x SBOM input), M7d done (GraalVM native-image binary),
M7e done (Gradle + Maven build plugins); M8 done (cacheable,
content-sensitive `checkReachability` task); M9 done (the analysis runs
in a forked worker process).

## Module layout (M7a)

Multi-module Gradle build: `core` holds the whole analysis pipeline (SBOM/OSV
parsing, SootUp call graph, verdicts, reports) plus the `AnalyzerEngine`
facade every front end calls in-process; `cli` is the picocli front-end +
Shadow fat JAR (`cli/build/libs/reachability-analyzer-0.1.0-SNAPSHOT-all.jar`);
`gradle-plugin` is the Gradle front end (M7e, `checkReachability` task);
`maven-plugin/` is the Maven front end (M7e, `reachability:check` goal) — a
separate Maven build inside the Gradle repo (recorded deviation, A10);
`tools:coveragetool` runs the per-package coverage gates against core's
JaCoCo data.

## Pinned toolchain & dependencies (verified 2026-10-05)

All pins live in `gradle/libs.versions.toml` (single source of truth).

| Component | Version |
|---|---|
| Gradle (wrapper) | 9.8.0 |
| JDK (runtime + build) | 25 (Temurin 25.0.3) |
| SootUp (`org.soot-oss` modules) | 3.0.1 (ASM 9.10.1; parses ≤ Java 25 bytecode) |
| Jackson (databind) | 2.22.3 |
| picocli | 4.7.7 |
| maven-artifact (`ComparableVersion`) | 3.9.16 |
| CycloneDX Maven plugin (target projects) | 2.9.1 |
| Shadow | 9.6.1 |
| Spock / Groovy (tests) | 2.4-groovy-4.0 / 4.0.32 |
| Checkstyle / JaCoCo | 10.4 / 0.8.15 |
| SpotBugs (tool, run via Gradle `spotbugsMain`) | 4.10.4 (ASM 9.10.1 — parses Java 25 bytecode) |

> The Fat-JAR is Java 25 bytecode: run it with a JDK 25 `java`, not an older one.

## Quick start

```bash
# 1. Build the Fat-JAR
./gradlew shadowJar

# 2. Download the OSV snapshot (writes osv-maven/ + the osv-maven.sha256 pin)
bash scripts/download-osv.sh osv-maven

# 3. Build the committed demo (Maven on purpose — cross-build-system proof):
#    CycloneDX SBOM at package time + the resolved dependency classpath
cd examples/vulnerable-demo
mvn -B package
mvn -B dependency:build-classpath -Dmdep.outputFile=target/cp.txt
cd ../..

# 4. Analyze
#    -XX:+UseCompactObjectHeaders (JEP 519, JDK 25, off by default) trims
#    the heap on object-heavy targets; the Fat-JAR needs JDK 25 anyway (A12).
java -XX:+UseCompactObjectHeaders -jar cli/build/libs/reachability-analyzer-0.1.0-SNAPSHOT-all.jar \
  --app-classes=examples/vulnerable-demo/target/classes \
  --classpath-file=examples/vulnerable-demo/target/cp.txt \
  --sbom=examples/vulnerable-demo/target/bom.json \
  --osv-dir=osv-maven \
  --osv-checksum="$(cut -d' ' -f1 osv-maven.sha256)" \
  --format=json,junitxml,sarif \
  --output=reachability-report
```

The demo pins log4j **2.14.1** (log4shell, `GHSA-jfh8-c2jp-5v3q`, and more):
the run exits **1** with 8 REACHABLE verdicts and full call traces in
`reachability-report.junit.xml`. Switching the pom's `log4j.version` to the
fixed release **2.25.5** makes the same run exit **0** with zero candidates
(2.25.5 sits at or beyond the fixed bound of every log4j record in the current
snapshot; verified 2026-10-07).

## CLI reference

| Option | Meaning |
|---|---|
| `--app-classes=<dir>` | Directory with the compiled application classes to analyze |
| `--classpath-file=<file>` | File with the resolved dependency classpath (colon- or newline-separated jar list) |
| `--sbom=<file>` | Path to the CycloneDX `bom.json` of the target project |
| `--osv-dir=<dir>` | Directory with local OSV Maven records |
| `--osv-checksum=<sha256>` | Expected sha256 of the OSV snapshot directory (A14 pinning); a mismatch fails with exit 2 |
| `--mappings=<file>` | Optional `vuln-mappings.json` (vuln id → class/method entries) |
| `--entry-points=<class#method,…>` | Explicit entry points; wins over auto-detection |
| `--callback-interfaces=<class#method,…>` | Additional callback interfaces for entry-point detection (extends the curated list, A13) |
| `--cha` | Build the call graph with CHA instead of RTA |
| `--pointer-analysis` | Build the call graph with SPARK object-sensitive pointer analysis instead of RTA (M7b; mutually exclusive with `--cha`, slower, prunes dispatch to receivers that are instantiated but never used at the call site) |
| `--java-version=<n>` | Expected Java version of the target (informational hint for the guard) |
| `--format=json,junitxml,sarif` | Report formats to write (json, junitxml, sarif; comma-separated; unknown token ⇒ exit 2) |
| `--output=<base>` | Base name for the generated reports (`<base>.json`, `<base>.junit.xml`) |
| `-v, --verbose` | Verbose diagnostics (entry points, CG size, durations, written files) |
| `-h, --help` / `-V, --version` | Usage / version |

Exit codes (A8): `0` = no reachable vulnerability (including zero candidates);
`1` = ≥ 1 REACHABLE; `2` = usage/config error; `3` = analysis failure (including
bytecode beyond the supported ceiling and a non-writable report destination).
A run that ends before report generation deletes any previous run's report
files under `--output`, so a green run never reads stale evidence.

## vuln-mappings.json (class/method-level precision)

OSV Maven records carry package-level data only, so default verdicts are
artifact-level. For critical CVEs, pin the vulnerable classes/methods
yourself:

```json
{
  "CVE-2021-44228": [
    {"class": "org.apache.logging.log4j.core.lookup.JndiLookup", "method": "lookup"}
  ],
  "CVE-2020-21570": [
    {"class": "org.apache.logging.log4j.core.config.reloader.ReconfiguringWatcher", "method": "run"}
  ]
}
```

Rules: the key is the OSV/GHSA id; each entry is `class` (+ `method`, optional
`descriptor` — without it any overload of the method matches). The file is
validated at startup (malformed ⇒ exit 2); vuln ids with no matching candidate
are ignored, ids present in the SBOM match but absent from the mapping fall
back to artifact-level with a report flag, and a mapping entry whose method is
absent from the call graph is UNREACHABLE (not an error).

## SBOM formats (A15)

`--sbom` accepts two JSON formats, auto-detected from the document:

- **CycloneDX 1.4–1.6** (`bomFormat: CycloneDX`) — the default, emitted by the
  CycloneDX Maven/Gradle plugins.
- **SPDX 2.x** (`spdxVersion: SPDX-2.x`, M7c) — packages are read from
  `externalRefs` purl entries; packages without a maven purl are skipped with
  a warning, same contract as CycloneDX.

SPDX **3.x** is refused with an explicit error naming the version ("only SPDX
2.x is supported") — exit 2, never a best-effort parse. An unrecognized
`bomFormat` or a document with neither marker is likewise an explicit error.

## SARIF findings (A9)

With `--format sarif` the run also writes `<output>.sarif` (SARIF 2.1.0) for
CI code-scanning UIs: one rule per candidate (the OSV record's summary as
`fullDescription`), one `error` result per REACHABLE vulnerability (the call
trace as the message, the component purl in the result `properties`, a
`physicalLocation` at the analyzed SBOM file, one logical location per path
hop). The physical location is the SBOM file because GitHub code-scanning
post-processing requires one per result, and its URI must match the
checkout's scheme (a `pkg:` purl fails that, so the purl stays in
`properties`); UNREACHABLE candidates are findings-format out by design —
the JUnit XML carries the full verdicts.

## Native image (M7d, A2)

A native binary of the same CLI builds from `:cli`:

```bash
JAVA_HOME=<GraalVM 25> ./gradlew :cli:nativeCompile
# binary: cli/build/native/nativeCompile/cli  (~21 MB, statically linked)
```

`--version` starts in single-digit milliseconds (measured 3–13 ms; the
fat JAR starts in ~2.7 s), and the full analysis produces verdict-identical
reports to the fat JAR — so CI can run the native binary instead of the
JVM. `build-analyzer.yml` carries the `native` job (GraalVM 25 runner);
`check` itself stays under plain Temurin and never builds the binary.

## Build plugins (M7e/M8, A10)

The same engine runs in-process from both build systems.

**Gradle** (`gradle-plugin`, plugin id `org.reachability`):

```kotlin
plugins {
    id("java")
    id("org.reachability")
}

reachability {
    bomFile = "target/bom.json"   // CycloneDX or SPDX 2.x SBOM of the project
    osvDir = "osv-maven"          // local OSV snapshot directory
    // optional: mappings, expectedOsvChecksum, entryPoints,
    // callbackInterfaces, cha, pointerAnalysis, formats ("json,junitxml,sarif"),
    // maxHeapSize (convention "1g" - heap of the forked analysis worker)
}
```

`checkReachability` (group `verification`) analyzes the main source set
(compiled classes + resolved runtime classpath) and fails the build when
any SBOM vulnerability is reachable; reports go to
`build/reachability-report.{json,junit.xml[,sarif]}`. The task is
`@CacheableTask` with content-sensitive inputs (app classes, classpath
jars, SBOM/OSV/mappings *content*) and declared outputs (the reports plus
`build/reachability-cp.txt`), so unchanged content is `UP_TO_DATE` and
identical content in a new directory is `FROM_CACHE` with `--build-cache`
— edit the SBOM or the OSV snapshot in place and the check re-runs. The
analysis runs in a **forked worker process** (process isolation;
`maxHeapSize`, convention `1g`), so a huge call graph cannot starve the
daemon — the worker announces its own pid in the output
("reachability: analysis runs in process N"), so out-of-memory failures
are attributable to the worker.

**Maven** (`maven-plugin`, built with the committed root `mvnw`):

```bash
# after the project's CycloneDX plugin wrote target/bom.json at package time
mvn org.reachability:reachability-maven-plugin:0.1.0-SNAPSHOT:check \
    -Dreachability.sbomFile=target/bom.json -Dreachability.osvDir=../osv-maven
```

`reachability:check` (default phase `verify`) reads the project's built
classes and resolved runtime classpath and fails the build the same way;
reports go to `target/reachability-report.{json,junit.xml[,sarif]}`.
Relative `-D` paths resolve against the project's basedir.
`scripts/maven-plugin-e2e.sh` proves the goal end-to-end on the demo
(vulnerable pin fails with reports, fixed pin passes) and runs as the
`maven-plugin` job in `build-analyzer.yml`.

## Precision limitations (A4)

- **Artifact-level default.** "Some class of the vulnerable artifact is
  reachable from a detected entry point" — low false-positive rate, but coarse:
  a reachable *safe* class of the artifact still yields REACHABLE. OSV Maven
  carries no class/method data (0 of 7,163 current records do), so this is the
  honest default; `--mappings` narrows it per CVE.
- **RTA (default) vs CHA (`--cha`) vs SPARK (`--pointer-analysis`).** RTA prunes
  to the reachable set from the entry points (SootUp 3.0.1's RTA already
  expands a virtual call only to *instantiated* subtypes) — fewer false
  positives, and it is what the gate relies on. CHA keeps dead code and
  over-approximates: use it to *compare*, not to pass. SPARK (M7b, A5) is the
  most precise, opt-in mode: its points-to analysis adds a call edge only when
  the receiver can actually point at the target, so an implementation that is
  instantiated somewhere but never dispatched at a call site is pruned
  (the RTA/CHA false positive).
- **Reflection / dynamic dispatch** (Spring wiring, `Class.forName`, SPI)
  defeats any static call graph. An artifact that is on the classpath but has
  no static path is reported UNREACHABLE **with `onClasspath: true`** and a
  console/JUnit-XML NOTICE ("possible reflection/dynamic dispatch risk") — the
  dangerous false-negative direction is made visible, not silent.
- **Entry points** = app-class `main()`, curated annotation handlers
  (controllers, `@Scheduled`, JMS/Kafka/Rabbit listeners, `@WebServlet`,
  Quartz), plus curated callback interfaces (A13). Extend with
  `--callback-interfaces`; the "every interface implementation" variant is
  deliberately not offered (it would collapse RTA precision).

## OSV snapshot operations

- `bash scripts/download-osv.sh [dest]` fetches
  `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip`
  (`curl -fL --retry 3`, ~10 MB, daily refresh) into `osv-maven/` and writes
  `osv-maven.sha256` next to it. The pin is the **same value** the analyzer
  computes from the directory (sha256 over `name:filesha256` lines,
  `LC_ALL=C`-sorted), so `--osv-checksum="$(cut -d' ' -f1 osv-maven.sha256)"`
  refuses a changed/tampered snapshot (mismatch ⇒ exit 2).
- The analyzer records the snapshot sha256 in report metadata on every run.
- **Air-gapped / corporate cache (R7):** publish the zip to
  Nexus/Artifactory as an ops step and unzip it in place of the download —
  `--osv-dir` is the only contract. Re-run `download-osv.sh` (or re-publish)
  to pick up new records; the pin travels with the data.

## CI/CD

- **`.github/workflows/reachability-check.yml`** — the consumer template (A7):
  JDK 25 → `download-osv.sh` → build the target (Maven: `mvn package` +
  `dependency:build-classpath`; Gradle variant documented inline) → run the
  analyzer (exit code captured) → **always upload the reports** → verify. On
  *this* repository it is a **living integration test that passes by
  design**: the committed demo pins the vulnerable 2.14.1, so the job passes
  when every id in `examples/vulnerable-demo/expected-reachable.txt` is
  reported REACHABLE and all three formats agree on the count (switching the
  pom to 2.25.5 makes it fail — zero candidates). In a consumer repository
  (no expected list) the gate semantics hold: fail when a vulnerability is
  reachable, pass on a clean run.
- **`Jenkinsfile`** — declarative pipeline: `Build & SBOM` → `OSV cache`
  (download once, `stash` across builds, pin verified on every build) →
  `Reachability Analysis` → archive `reachability-report.*` on every outcome.
  The pipeline fails naturally on analyzer exit 1/2/3; no special handling.
  Requirements: JDK 25 + Maven on the agent; the analyzer builds with the
  committed `./gradlew` wrapper.
- **`.github/workflows/build-analyzer.yml`** — CI for the tool itself
  (`./gradlew check` on push/PR).
- **`renovate.json5`** — dependency updates via [Renovate](https://docs.renovatebot.com):
  PRs for the version catalog, the Gradle/Maven wrappers, the
  `maven-plugin` toolchain, and the GitHub Actions.
  `examples/vulnerable-demo` is excluded (its vulnerable log4j pin is
  deliberate — T65) and `osv-maven` is a data artifact, not a dependency
  (A14). Activating the bot is a manual step: install the Renovate app
  (or bot) on the repository.

## Bytecode-version guard

SootUp 3.0.1 parses class files up to Java 25 (major 69) and **silently**
returns zero classes for anything newer. The analyzer probes the target's
max class-file version and exits `3` beyond the ceiling (regression fixtures
in `src/test/resources/fixtures/bytecode/`).

## Coverage gate

`./gradlew check` runs the `coverageGate` task, which evaluates the test
execution data against the plan's gates (sbom/osv/report 100% line, analysis
≥ 90% branch) via `org.reachability.coveragetool.CoverageGate`. It replaces
Gradle's `jacocoTestCoverageVerification` task, whose ant worker in Gradle 9.x
evaluates the execution data as empty and would pass vacuously (see ADR 0018).

## License / origin

Greenfield project; see `docs/adr/` (0001 overview + index, one ADR per
decision 0002–0017, ops ADRs 0018–0019) and `implementation-plan.md`.
