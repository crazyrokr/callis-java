# Implementation Plan — Dependency Vulnerability Reachability Analyzer

> Companion to `plan.md` (feature spec). This document is the execution-ready plan:
> verified stack, repo layout, task-level workstreams, test strategy, and acceptance
> criteria. Status: **planning** (repo is greenfield — only `plan.md` exists).

---

## 1. Executive Summary

Build a standalone Java CLI (Fat-JAR) that answers one question in CI:
**"Is this vulnerability in the SBOM actually reachable from application code?"**

Pipeline: `CycloneDX SBOM` + `local OSV database` → *candidate vulnerabilities*
→ `SootUp call graph` (entry points → app bytecode + library jars)
→ *REACHABLE / UNREACHABLE* verdicts with call traces → JSON + JUnit XML reports.
Exit code `1` on any reachable vulnerability (fail the pipeline), `0` otherwise.

**Honest capability boundary (decides the whole design):** OSV Maven records carry
package-level `affected`/`ranges` data — they do **not** contain class/method
signatures (contrary to `plan.md` step 4.1). Reachability is therefore:

- **default: artifact-level** — "some class of the vulnerable artifact is reachable
  from an entry point" (low false-positive rate, but coarse);
- **optional: class/method-level** — via a local mapping file
  `vuln-mappings.json` (vuln ID → classes/methods) or, where an advisory documents
  them, OSV `database_specific` fields.

This trade-off is documented in the ADRs (§4) and is the #1 risk (§8).

**Bytecode support (verified 2026-10-05):** the analyzer runs on Java 25 and
analyzes projects built with **Java 25 or older** — SootUp 3.0.1 (ASM 9.10.1)
parses v69 class files, confirmed by direct test under a Java 25 runtime.
SootUp *silently* returns zero classes for bytecode versions it does not
handle (verified: v69 under 2.0.0, v70 under 3.0.1), so M3 adds a hard
startup guard — probe the target's max class-file version and fail with
exit 3 when a non-empty directory parses to nothing (A12/R8).

---

## 2. Tech Stack (versions verified 2026-10-05)

| Component | Choice | Pinned version | Notes / verification |
|---|---|---|---|
| Build | **Gradle 9.8.0** (wrapper committed) | 9.8.0 (current stable, 2026-09-24) | Kotlin DSL; `gradle/libs.versions.toml` version catalog pins every dependency in one place |
| Runtime | **Java 25 LTS** | 25.0.x (Temurin / GraalVM CE) | Verified 2026-10-05: Gradle 9.x runs on Java 17–27 (Java 25 needs ≥ 9.1.0); Spock 2.3 + Groovy 4.0.32 pass specs under 25; SootUp 3.0.1 runs under 25 and parses ≤ Java 25 bytecode under 25 (verified). Compile with `--release 17` only if the Fat-JAR must also run on older JDKs |
| Bytecode analysis | **SootUp** `org.soot-oss:sootup.core` / `sootup.java.core` / `sootup.java.bytecode.frontend` / `sootup.jimple.frontend` / `sootup.callgraph` | **3.0.1** | Published on Maven Central (verified on repo1.maven.org 2026-10-05 — the Solr search index lags and still shows 2.0.0). ASM 9.10.1; API verified: `JavaView` + `JavaClassPathAnalysisInputLocation` + `RapidTypeAnalysisAlgorithm` / `ClassHierarchyAnalysisAlgorithm` (same surface as 2.0.0) |
| JSON | `com.fasterxml.jackson.core:jackson-databind` | latest 2.x (verify at M0) | OSV records, CycloneDX SBOM, reports |
| CLI | `info.picocli:picocli` | latest 4.x | Argument parsing, help text, exit codes |
| Maven version comparison | `org.apache.maven:maven-artifact` → `ComparableVersion` | 3.9.x | OSV Maven ranges are not strict semver (`1.0`, `1.0-SNAPSHOT`, `RELEASE`); `ComparableVersion` is the de-facto standard |
| SBOM generation (target projects) | `org.cyclonedx:cyclonedx-maven-plugin` | **2.9.1** | `plan.md` says 2.8.0 — outdated. Gradle side: `org.cyclonedx.bom` plugin, latest 2.x |
| OSV data | `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` | — | **Verified live: ~10.3 MB, refreshed daily** (last-modified 2026-10-02). Small enough for direct CI download; corporate Nexus/Artifactory cache optional for air-gapped envs |
| Packaging | Shadow plugin `com.gradleup.shadow` | 9.0.0-beta12 | Fat-JAR via `shadowJar`, `Main-Class` = CLI entry, `mergeServiceFiles()`, exclude `module-info.class` + `META-INF/*.sig`. If the beta pin is unacceptable: Gradle 8.x + `com.github.johnrengelman.shadow` 8.3.6 (now in maintenance) |
| Native (optional, M7) | GraalVM native-image | JDK 17/21 | Stretch goal only |
| Tests | **Spock** `org.spockframework:spock-core` | **2.3-groovy-4.0** (latest GA; 2.4-M6 exists — re-check at M0) | Groovy specs; native `given:/when:/then:` (the mandated test convention, as a language construct), built-in assertions (replaces AssertJ), built-in mocks/stubs, data-driven `where:` tables |
| Test language | `org.apache.groovy:groovy` | **4.0.32** | Groovy 4 line — Spock 2.3 targets `groovy-4.0` (Groovy 5.0 is out but has no Spock variant yet). Main code stays 100% Java; Groovy lives only under `src/test/groovy` |
| Static analysis of *our own* code | SpotBugs + Checkstyle | — | Configured at M0; run before every milestone closes |

**Deliberate non-choices**
- `org.apache.maven:maven-artifact` in the table above is a **library** dependency
  (`ComparableVersion` for OSV range math) — no coupling to a Maven build.
- No `cyclonedx-core-java` library: `bom.json` is plain JSON; a small Jackson parser
  (components → purl, name, version) keeps dependencies thin and testable.
- No AssertJ / Mockito: Spock's built-in assertion syntax and Groovy MOP
  `Mock()`/`Stub()` cover it — one assertion and mock style across all specs (A11).
- No network calls at analysis time — fully offline by design (air-gap requirement).
- No database: OSV files are read from a local directory (`--osv-dir`).

---

## 3. Repository Layout

```
dependency-vulnerability-analyzer/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle/libs.versions.toml
├── gradlew, gradlew.bat + gradle/wrapper/
├── README.md
├── implementation-plan.md            # this file
├── docs/
│   └── adr/
│       ├── 0001-architecture.md      # overview + index (corrections, pins)
│       └── 0002…0019-*.md           # one ADR per decision (A1–A16) + ops ADRs
├── scripts/
│   └── download-osv.sh              # Phase 3 helper
├── .github/workflows/
│   ├── build-analyzer.yml           # CI for the tool itself (M0)
│   └── reachability-check.yml       # Phase 6 consumer workflow (M6)
├── Jenkinsfile                       # Phase 6 (M6)
├── examples/
│   └── vulnerable-demo/             # tiny Maven app w/ known-vuln dep (M4/M6)
│       ├── pom.xml
│       └── src/main/java/...
└── src/
    ├── main/java/org/reachability/analyzer/
    │   ├── ReachabilityAnalyzerCli.java   # picocli @Command (M1)
    │   ├── sbom/                          # M1
    │   │   ├── CycloneDxParser.java
    │   │   ├── SbomComponent.java         # name, version, purl
    │   │   └── Purl.java                  # pkg:type/namespace/name@version
    │   ├── osv/                           # M2
    │   │   ├── OsvRecord.java             # id, summary, affected[], ranges
    │   │   ├── OsvRepository.java         # dir scan + parse + index by name
    │   │   ├── AffectedRange.java
    │   │   ├── VersionRangeMatcher.java   # ComparableVersion-based
    │   │   └── VulnerabilityCandidate.java# (component, record, matched range)
    │   ├── analysis/                      # M3/M4
    │   │   ├── AnalysisContext.java       # app classes, jar list, JavaVersion
    │   │   ├── SootUpSetup.java           # JavaClassProvider + source locators
    │   │   ├── EntryPointDetector.java    # main(), @RestController, @Scheduled, ...
    │   │   ├── CallGraphFactory.java      # RTA default, CHA option
    │   │   ├── ReachabilityChecker.java   # target-in-reachable-set?
    │   │   ├── CallPathFinder.java        # BFS predecessor map → one path
    │   │   └── VulnMappingLoader.java     # vuln-mappings.json (M4)
    │   └── report/                        # M5
    │       ├── AnalysisReport.java        # model
    │       ├── JsonReportWriter.java
    │       └── JUnitXmlReportWriter.java  # 1 <testcase> per vulnerability
    └── test/
        ├── groovy/org/reachability/analyzer/...   # Spock specs, mirror main 1:1
        └── resources/fixtures/
            ├── osv/                      # real records from all.zip (see §6)
            ├── bom.json
            ├── mappings/
            └── mini-app/                 # compiled stub "library" + caller classes
```

Package root `org.reachability.analyzer` is a placeholder — rename in M0 if a
corporate groupId is preferred.

---

## 4. Architectural Decisions — per-decision ADRs

All decisions below are recorded **once each** in `docs/adr/`:
`0001-architecture.md` is the overview + index (created in M0), A1–A16 each
own an ADR (`0002`–`0017`, stable `A#` labels), and later changes amend the
specific decision ADR in place (split 2026-10-10).

| # | Decision | Rationale |
|---|---|---|
| A1 | SootUp 3.0.1 over classic Soot / ASM-only | Modern API, Jimple IR, maintained; CHA + RTA call graphs out of the box; 3.0.1 published on Central and parses ≤ Java 25 bytecode (verified) |
| A2 | Fat-JAR via Shadow (`shadowJar`) as v1 packaging; GraalVM native via `org.graalvm.buildtools.native` deferred to M7 | Instant-start CI goal is nice-to-have; SootUp's reflective use may need native-image reflect config — don't block v1. The GraalVM Gradle native plugin is the first-class supported path, which also favors choosing Gradle |
| A3 | Offline OSV via local directory + `download-osv.sh` | Air-gapped requirement; 10 MB zip makes CI download trivially cheap; corporate cache is an ops option, not an app dependency |
| A4 | Artifact-level reachability default; class/method-level only via optional mapping file | OSV has no method data for Maven (see §1). Default must not overpromise precision; mapping file gives escape hatch for critical CVEs |
| A5 | RTA (`IntraProceduralCallGraphBuilder`) default, CHA flag `--cha` | RTA prunes to reachable set from entry points → fewer false positives from dead code; CHA is the cheaper/faster fallback. Pointer-analysis (Heros) precision = M7 stretch |
| A6 | Entry points = `main()` in app classes + annotation-driven (Spring `@RestController`/`@RequestMapping` handlers, `@Scheduled`, JMS/Kafka/Rabbit listeners, `@WebServlet`, Quartz `@ScheduledJob`/`execute()`) | Covers the frameworks in plan.md step 4.3 without hard dependencies on the frameworks themselves — annotations are read from bytecode, not classpath types |
| A7 | Classpath scope = **resolved** dependency set from SBOM + app classes (not `~/.m2/repository`) | `plan.md` Phase 6 uses `--classpath=~/.m2/repository` — impractical (GBs, unrelated jars, slow CG) and a precision hazard. For a Maven target use `mvn dependency:build-classpath -Dmdep.outputFile=cp.txt`; for a Gradle target a small custom task writing `cp.txt`. (These commands run in the *analyzed* project only — the tool itself is built with Gradle, no conflict) and intersect with SBOM purls |
| A8 | Exit codes: `0` = no reachable vulns; `1` = ≥1 REACHABLE; `2` = usage/config error; `3` = analysis/runtime failure | Plan specifies 0/1; 2/3 distinguish "broken invocation" from "analyzer crashed" so CI can react differently |
| A9 | Reports: JSON (machine) + JUnit XML (CI badge/visualization) | Per plan Phase 5; one `<testcase>` per vulnerability, fail when REACHABLE |
| A10 | Single Gradle project (one `build.gradle.kts`) for v1 | Keep it simple; split `core`/`cli` only if a library consumer appears |
| A11 | **Spock (Groovy 4) as the test framework** — not JUnit 5 + AssertJ | Spock's `given:/when:/then:` is the mandated test structure as a language construct; built-in assertions drop the AssertJ dependency (one assertion style across the codebase); `where:` data tables make the M2 edge-case matrix one table per event shape; mocks are built-in. Production code remains pure Java |
| A12 | **Java 25 LTS runtime; target-bytecode ceiling = Java 25** under SootUp 3.0.1 (ASM 9.10.1) | Verified 2026-10-05: Gradle 9.x supports Java 25 (≥ 9.1.0); Spock 2.3 + Groovy 4.0.32 pass under 25; SootUp 3.0.1 runs under 25 and parses v69 (Java 25) class files. SootUp **silently returns an empty class list** for bytecode versions it does not handle (verified: v69 under 2.0.0, hand-crafted v70 under 3.0.1) — without a guard, a target built with newer bytecode would pass with zero findings (false negative). M3 keeps a startup guard: probe max class-file major version + zero-classes-from-non-empty-dir check, **exit 3** beyond the supported ceiling |
| A13 | **Bounded callback-interface entry points** | Enterprise code reaches vulnerable code via framework callbacks (Servlet `Filter`, Quartz `Job`, Spring `ApplicationListener`, JMS listeners) that no annotation scan catches. SootUp 3.0.1 exposes `JavaSootClass.getInterfaces()`, so app classes implementing a **curated, user-extensible** callback list (`--callback-interfaces`) become entry points. The "all interface implementations" variant is rejected: it would admit every business interface, inflating entry points and collapsing RTA precision (more false positives for a security gate) |
| A14 | **OSV snapshot pinning + fail-safe parsing + classpath NOTICE** | TLS already covers transit integrity; the real enterprise need is reproducibility: `download-osv.sh` writes an `osv-maven.sha256` pin, the analyzer records the sha256 in report metadata, optional `--osv-checksum` verifies. Robustness: malformed records skipped with a count; **zero valid records → exit 3**; `withdrawn` records (113 in the current dump) are never indexed. Report carries `onClasspath` + a reflection/dynamic-dispatch NOTICE for UNREACHABLE-but-present artifacts (closes the 1A "quick win" without any method-data dependency) |
| A15 | **SBOM-format agnosticism via `SbomParser`** | CycloneDX now (interface + auto-detect from `bomFormat`/`spdxVersion`); SPDX **JSON** in M7; SPDX XML excluded from v1 (XML dependency for marginal gain). Enterprises split between the two formats; the interface makes each new format one class |
| A16 | **Caching & parallelism deferred, benchmark-gated** | SootUp 3.0.1 caches are in-memory only (LRU/Full; no CG serialization API — `DotExporter` is visualization, `JimpleBodySerializer` is text) and `GraphBasedCallGraph` is not thread-safe. Full-CG disk caching rejected for v1: app classes change every commit, so the cache key almost always misses in CI; a JAR-level SHA-256 parse cache and snapshot-based parallel path-finding are M7 stretch items, implemented only if an M4 benchmark on a medium real project shows parse/path work dominates |

---

## 5. Workstreams (ordered by dependency)

Task format: `T## — task`. Each workstream ends with **acceptance criteria**
that must be green before the next starts. Tests are written **before** the
implementation they pin (see §6).

### M0 — Bootstrap (≈ 0.5 day)
- T01 Gradle project: `settings.gradle.kts` + `build.gradle.kts` (Kotlin DSL),
  **Java 25 toolchain**, `application` + `groovy` + Shadow plugins; `shadowJar` configured with
  `Main-Class`, `mergeServiceFiles()`, exclusions for `module-info.class` +
  `META-INF/*.sig`; `groovy` plugin with `test { useJUnitPlatform() }` and
  `src/test/groovy` source set (Spock 2.x runs on the JUnit Platform).
  Commit Gradle 9.8.0 wrapper + `gradle/libs.versions.toml`
  (all version pins in the catalog).
- T02 Checkstyle + SpotBugs (main Java) + JaCoCo (Groovy 4 supported since
  0.8.7) Gradle plugins wired into `./gradlew check`; Spock + Groovy 4 test
  setup verified with one trivial passing spec; green on the empty skeleton.
- T03 `.github/workflows/build-analyzer.yml`: `actions/setup-java` (Gradle
  caching) + `./gradlew build` on push (CI for the tool itself, independent of
  M6 consumer workflow).
- T04 Create `docs/adr/0001-architecture.md` with A1–A16.
- T05 Verify dependency pins resolve via `./gradlew dependencies` (SootUp 3.0.1
  modules, Jackson, picocli, maven-artifact); record versions in README;
  re-check Shadow 9.0.0 GA availability; confirm 3.0.1 parses a
  `--release 25` fixture and that the v70 guard fires (both already done
  during planning — keep as regression).

**Accept:** `./gradlew shadowJar` produces a runnable Fat-JAR
(`java -jar build/libs/...jar --help` prints usage); `./gradlew check` green;
CI green; ADR committed.

---

### M1 — CLI skeleton + SBOM parsing (≈ 1 day)
- T11 `ReachabilityAnalyzerCli` (picocli): options `--app-classes`,
  `--classpath-file`, `--sbom`, `--osv-dir`, `--mappings` (optional),
  `--cha`, `--java-version`, `--output`, `--format=json,junitxml`,
  `--verbose`. Exit-code contract A8 wired through a single
  `CliResult` enum — no scattered `System.exit`.
- T12 `Purl` model: parse/normalize `pkg:maven/<group>/<name>@<version>`
  (group optional in some records; version optional in OSV purls).
- T13 `SbomParser` interface + `CycloneDxParser` implementation (A15):
  `bom.json` v1.4/1.5 → `List<SbomComponent>` (`name`, `version`, `purl`,
  `bom-ref`); format auto-detected from `bomFormat` (CycloneDX) vs
  `spdxVersion` (SPDX — parser lands in M7). Skip components without purl
  with a warning; `bom-<name>` refs ignored.

**Tests first** (`PurlSpec`, `CycloneDxParserSpec`): parser against a real
`bom.json` fixture (from an actual `mvn package` run, committed); edge cases —
missing purl, missing version, nested `components`, unknown spec version,
unknown/missing `bomFormat` (explicit error, not a crash).

**Accept:** `cli --sbom fixtures/bom.json --dry-run-sbom` (hidden debug flag)
prints the component table; 100% line coverage on `sbom/`; all Given-When-Then.

---

### M2 — OSV matching + version-range engine (≈ 2 days; the core logic)
- T21 `OsvRepository`: scan `--osv-dir/*.json`, parse to `OsvRecord`, build
  in-memory index keyed by **normalized name** — verified against all 7,163
  records of the current dump: `affected[].package.name` is
  `group:artifact` in 5,471 of 5,674 affected entries vs 203 plain, so index
  the raw name *and* the purl name part (`pkg:maven/<group>/<name>`).
  **Skip `withdrawn` records (113 exist)**. Use
  `affected[].database_specific.last_known_affected_version_range` (352
  records) as a `last_affected` boundary hint when no `fixed` event is
  present. Parse `affected[].ranges[].events`
  (`introduced`/`fixed`/`last_affected`).
- T21b Robust parsing (A14): malformed record → warn + skip + count;
  **zero valid records from a non-empty directory → exit 3** (fail-safe);
  parse-skip count and OSV snapshot sha256 recorded in report metadata.
- T22 `VersionRangeMatcher` (pure, no I/O): given `version` + `ranges`
  (+ optional explicit `versions` list fallback) → affected? which range?
  Uses `ComparableVersion` from maven-artifact.
- T23 `VulnerabilityCandidate` assembly: for each SBOM component × index hits
  → candidates with vuln id, summary, matched range, affected-version evidence.
  Dedup: same vuln id + component ⇒ one candidate.
- T24 CLI plumbing: `--dry-run-match` mode stops here, prints candidates,
  exit 0 (used in M6 before SootUp is wired).

**Tests first (edge cases = the point of this workstream)** — as `VersionRangeMatcherSpec`
with one Spock `where:` data table per case family (version × event shape →
affected?):
- `introduced=0, fixed=2.15.0`: `2.14.1` affected; `2.15.0` **not**; `2.16.0` not.
- No `fixed` event ⇒ all `≥ introduced` affected.
- `last_affected=1.12.0` ⇒ `1.11.0` affected, `1.12.1` **not** (strictly greater).
- Multiple ranges on one record (OR semantics), multiple `affected` entries.
- Maven oddballs: `1.0` vs `1.0.0`, `1.0-SNAPSHOT`, `1.0-RELEASE`,
  `1.0-alpha1` ordering — each pinned with a case.
- **False-positive guard:** version *equal* to `fixed` must not match;
  `introduced` inclusive.
- Explicit `versions` list fallback when `ranges` empty.
- Real-record fixtures pulled from `all.zip` at M0 (include
  `CVE-2021-44228` (log4j-core), one `last_affected` example, one with
  multiple affected packages, one `withdrawn` record, one `group:artifact`
  name (the dominant form), one with `last_known_affected_version_range`);
  record the snapshot sha256 next to the fixtures (pinning, A14).

**Accept:** ≥ 90% branch coverage on `osv/`; matcher 100%; fixture suite green.

---

### M3 — SootUp integration + call graph (≈ 2–3 days; integration-heavy)
- T31 `SootUpSetup` (verified 3.0.1 API): build `JavaView` over
  `JavaClassPathAnalysisInputLocation(appClasses + ":" + jars from
  --classpath-file)` — one colon-joined classpath string covers app classes
  and all jars.
  **Bytecode guard (A12):** probe the highest class-file major version across
  app classes; > 69 (Java 25 ceiling under SootUp 3.0.1 — v70 parses to
  *silently* zero classes) → **exit 3** with a clear message before any
  analysis. Also fail loudly if a non-empty class directory parses to zero
  classes; record the detected version in report metadata.
- T32 `EntryPointDetector`:
  - `main(String[])` in **app classes only** (never library mains);
  - annotation scan over app classes: Spring controllers/handlers,
    `@Scheduled`, JMS/Kafka/Rabbit listener interfaces (`onMessage` etc.),
    `@WebServlet`/`doGet`/`doPost`, Quartz `execute`.
  - `--entry-points` override (explicit `class#method` list, wins over auto).
  - **Callback-interface entry points (bounded, A13):** app classes
    implementing a curated framework callback list become entry points
    (e.g. `javax.servlet.Filter#doFilter`, `org.quartz.Job#execute`,
    `org.springframework.context.ApplicationListener#onApplicationEvent`,
    `javax.jms.MessageListener#onMessage`); `--callback-interfaces` extends
    the list. `JavaSootClass.getInterfaces()` verified in SootUp 3.0.1.
    Deliberately **not** "every interface implementation" — that would admit
    all business interfaces, inflating entry points and collapsing RTA
    precision (more false positives).
- T33 `CallGraphFactory` (verified 3.0.1 API): RTA via
  `RapidTypeAnalysisAlgorithm` (default) or CHA via
  `ClassHierarchyAnalysisAlgorithm` (`--cha`); both `initialize(entryPoints)`
  on the same `JavaView`. Log CG size + build time at `--verbose`.
- T34 Diagnostics: missing-jar warnings (jar listed in classpath file but
  unreadable), classes skipped due to version mismatch, memory guard
  (`-Xmx` guidance in error message on `OutOfMemoryError`).

**Tests first (integration-grade, small by design):**
- **Bytecode guard:** `--release 25` fixture → parses fine (3.0.1 ceiling,
  verified); hand-crafted v70 (Java 26) class file → exit 3 + guard message
  (3.0.1 returns `[]` — silently — for v70, confirmed during planning).
- **Callback interfaces:** app class implementing a Quartz `Job` →
  `execute()` is an entry point and a call through it is reachable; app
  class implementing a plain business interface → **not** an entry point
  (precision guard).
- `mini-app` fixture: two stub jars (`stublib` with `safe()`/`danger()`),
  app class calling `safe()` only → CG includes `safe()`, **excludes**
  `danger()` (RTA prunes it) — false-positive scenario pinned.
- App calling `danger()` → present in reachable set.
- Entry-point detection: fixture classes for `main`, `@RestController`,
  `@Scheduled`, listener interface — positive + negative (library `main`
  excluded).
- CHA vs RTA same fixture: document the difference (CHA may keep dead code).

**Accept:** all `analysis/` unit tests green; `--dry-run-graph` debug mode
dumps CG node count; build-time on `examples/vulnerable-demo` < 60 s.

---

### M4 — Reachability verdicts + path extraction (≈ 2 days)
- T41 `ReachabilityChecker`:
  - artifact-level: reachable set ∩ any class of the vulnerable artifact
    (artifact id → package prefix mapping via the jar's entries:
    `org/apache/logging/log4j/core/*`);
  - class/method-level (when `--mappings` provides the vuln id →
    `class#method[descriptor]` entries): exact `MethodSourceLocator` match.
  - Result per candidate: `REACHABLE` / `UNREACHABLE` /
    `NO-CLASS-INFO` (mapping absent → artifact-level used, flag in report).
  - **`onClasspath` flag (A14):** artifact present in the parsed view but no
    class reachable → `UNREACHABLE` + `onClasspath: true` (M5 emits a
    reflection/dynamic-dispatch NOTICE); artifact absent entirely → plain
    `UNREACHABLE`.
- T42 `VulnMappingLoader` + `vuln-mappings.json` schema:
  `{"CVE-2021-44228": [{"class":"org.apache.logging.log4j.core.impl.JndiLookup","method":"lookup"}]}`
  — validated at startup, unknown vuln ids warned.
- T43 `CallPathFinder`: BFS from entry points over CG, predecessor map,
  emit **one** shortest path per reachable candidate
  (entry point → … → vulnerable class/method) with per-hop `class#method`.
- T44 Exit-code decision: any `REACHABLE` ⇒ exit `1` + `CRITICAL` log line per
  vuln; all `UNREACHABLE` ⇒ exit `0` + `NOTICE` lines; zero candidates ⇒ exit `0`
  + summary.

**Tests first:**
- mini-app positive: path `main → service.call → stublib.danger` asserted
  hop-by-hop.
- mini-app negative: `danger()` exists in jar, never called ⇒ UNREACHABLE,
  exit 0 (the flagship false-positive test).
- Mapping present but method absent from CG ⇒ UNREACHABLE (not an error).
- Two entry points reaching same vuln ⇒ exactly one path in report
  (determinism: lexicographic first).

**Accept:** `examples/vulnerable-demo` (log4j-core 2.14.1, JNDI lookup
exercised by a controller) ⇒ exit 1, trace printed; same app with the call
commented out ⇒ exit 0. Record CG build time + total runtime here as the
baseline for the A16 benchmark (re-run on a medium real project before
scoping M7 cache/parallelism work).

---

### M5 — Reporting engine (≈ 1 day)
- T51 `AnalysisReport` model: run metadata (tool version, CG builder,
  entry-point count, CG size, duration, detected target bytecode version,
  OSV snapshot sha256, OSV parse-skip count), per-vulnerability entries:
  vuln id, component `purl`, `REACHABLE|UNREACHABLE`, `onClasspath`,
  severity (from OSV `severity`/`database_specific` when present),
  `affectedRange`, `path[]` (when reachable).
- T52 `JsonReportWriter` (Jackson, pretty-print, stable key order).
- T53 `JUnitXmlReportWriter`: one `<testsuite name="reachability">`, one
  `<testcase name="<vuln-id> <purl>">` per candidate; REACHABLE ⇒
  `<failure message="reachable">` with trace in body; UNREACHABLE ⇒ pass with
  `<skipped>`-style note (keeps badges honest: suite "fails" exactly when
  pipeline must fail).
- T54 Console output: human summary table (id, component, verdict, path head)
  + `--verbose` details; never duplicates the full report. Per
  UNREACHABLE-but-`onClasspath` vulnerability: NOTICE line — "artifact
  present in classpath but no static path found — possible
  reflection/dynamic-dispatch risk" (quick win, A14).

**Tests first:** golden-file tests — fixture candidates → exact JSON
(round-trip parse), XML well-formedness + failure/passage semantics per verdict.

**Accept:** both writers at 100% line coverage; golden files committed.

---

### M6 — CI/CD integration + docs (≈ 1.5 days)
- T61 `scripts/download-osv.sh`:
  ```bash
  set -euo pipefail
  URL="https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
  DEST="${1:-osv-maven}"
  tmp="$(mktemp)"
  curl -fL --retry 3 -o "$tmp" "$URL"
  mkdir -p "$DEST" && unzip -oq "$tmp" -d "$DEST" && rm -f "$tmp"
  ```
  (URL verified 2026-10-05: HTTP 200, ~10.3 MB, daily refresh.)
  Also writes `osv-maven.sha256` next to the directory — snapshot pinning for
  reproducible builds (A14); the analyzer records the sha256 in report
  metadata and accepts optional `--osv-checksum <sha256>`.
- T62 `.github/workflows/reachability-check.yml` (consumer template, per
  plan.md Phase 6, **corrected per A7**):
  1. checkout + JDK 25 (analyzer runtime; A12)
  2. `download-osv.sh` (or restore corporate cache)
  3. Maven target: `mvn package` (CycloneDX 2.9.1 → `target/bom.json`) **and**
     `mvn dependency:build-classpath -Dmdep.outputFile=target/cp.txt`;
     Gradle target: `./gradlew cyclonedxBom` + a small custom task that writes
     `target/cp.txt` (documented in the template)
  4. run analyzer (jar built via `./gradlew shadowJar` in the analyzer repo,
     published to the corporate repo, or checked out + built in the workflow):
     `java -jar reachability-analyzer.jar --app-classes=target/classes \
        --classpath-file=target/cp.txt --sbom=target/bom.json \
        --osv-dir=osv-maven --mappings=... (optional) \
        --format=json,junitxml --output=reachability-report`
  5. `actions/upload-artifact` for both reports.
- T63 `Jenkinsfile`: declarative — stages `Build & SBOM` → `OSV cache`
  (stash/cache) → `Reachability Analysis` → archive `reachability-report.*`;
  analyzer built with the committed `./gradlew` wrapper (or `withGradle`
  tool); pipeline fails on exit 1 (natural, no special handling).
- T64 README: quick start, CLI reference, `vuln-mappings.json` guide,
  precision-limitations section (A4), OSV cache ops note.
- T65 `examples/vulnerable-demo` committed (pom pins vulnerable version,
  CycloneDX plugin, sample workflow invocation; buildable with any JDK ≤ 25 —
  A12) — living integration test. Intentionally a **Maven** demo while the
  tool itself is Gradle: it proves cross-build-system analysis end-to-end.

**Accept:** running the GH workflow on `examples/vulnerable-demo` in a
throwaway fork fails with the JUnit XML attached; switching the demo dep to
the fixed version makes it pass. Jenkinsfile reviewed for syntax (lint).

---

### M7 — Stretch (post-v1, only if requested)
- GraalVM native-image build (A2) via `org.graalvm.buildtools.native` plugin —
  expect reflect-config work for SootUp; budget 1–2 days, gate on
  startup < 500 ms.
- Pointer-analysis precision mode (`sootup.analysis.interprocedural` / Heros
  IFDS) for receiver-sensitive dispatch — large accuracy win, real cost.
- Gradle-native SBOM path (`org.cyclonedx.bom` plugin) in the consumer
  template.
- SARIF output for GitHub code scanning.
- **Gradle + Maven plugins** — `checkReachability` (Gradle) /
  `reachability:check` (Maven) wrapping the engine; **triggers the A10
  module split** (`core` / `cli` / `gradle-plugin` / `maven-plugin`);
  auto-wires the CycloneDX SBOM + classpath-file tasks so users never touch
  CLI arguments.
- **SPDX JSON parser** behind `SbomParser` (A15).
- **JAR-level parse cache** keyed by SHA-256 (A16) — SootUp 3.0.1 has
  in-memory caches only; implement only if the M4 benchmark shows parsing
  dominates on a medium real project. Full-CG disk caching stays rejected
  (app classes change every commit → rare hits).
- **Parallel candidate path-finding** over an immutable CG snapshot
  (A16) — `GraphBasedCallGraph` is not thread-safe in 3.0.1, so parallelize
  over a snapshot built once; benchmark-gated like the cache.

---

## 6. Test Strategy (binding, per project rules)

- **Order:** regression/characterization tests exist **before** the code they
  constrain — M2 (range engine), M3 (CG fixtures), M4 (reachability) all start
  with their test suites.
- **Structure:** every Spock spec uses native `given: / when: / then: / and:`
  blocks (the mandated convention, built into the framework — A11); feature
  method names follow `given<state>_when<action>_then<expectation>`.
- **False-positive scenarios are first-class** (this is a security gate —
  false "reachable" blocks releases, false "unreachable" hides CVEs):
  - method exists in vulnerable jar but is never called → UNREACHABLE;
  - call behind dead branch pruned by RTA → UNREACHABLE;
  - version == `fixed` → not vulnerable;
  - library `main()` → never an entry point.
- **Fixtures over mocks** where possible: real OSV records from `all.zip`
  (pinned copies in `src/test/resources/fixtures/osv/`), a real `bom.json`
  (generated once via `mvn package` on `examples/vulnerable-demo`), real
  compiled classes for `mini-app`. Where a boundary must be stubbed (e.g.
  SootUp's `JavaClassProvider` in `SootUpSetup` tests), use Spock's built-in
  `Mock()`/`Stub()` — no Mockito.
- **Coverage gate:** JaCoCo (Groovy 4 supported since 0.8.7; pin latest
  0.8.x) — 100% line on `osv/` and `report/`, ≥ 90% branch on `analysis/`
  (main Java); enforced in CI, milestone cannot close red.
- **Full-suite rule:** before any milestone closes, `./gradlew check`
  (tests + Checkstyle + SpotBugs + JaCoCo) is run clean — no red carried forward.
- **E2E:** `examples/vulnerable-demo` driven via the built Fat-JAR from the
  shell (plain shell invocation from a Spock feature method or from the M6
  workflow) asserting exit code **and** report content.

---

## 7. Deliverables Checklist

- [ ] `reachability-analyzer-<v>.jar` (Shadow Fat-JAR, Main-Class set)
- [ ] Gradle wrapper + `gradle/libs.versions.toml` committed
- [ ] `docs/adr/` (0001 index + 0002–0017 per-decision ADRs A1–A16 + 0018/0019 ops)
- [ ] `scripts/download-osv.sh`
- [ ] `.github/workflows/{build-analyzer,reachability-check}.yml`
- [ ] `Jenkinsfile`
- [ ] `examples/vulnerable-demo/` (red and green variants demonstrated)
- [ ] README (quick start, CLI ref, precision caveats, ops notes)
- [ ] Green `./gradlew check` incl. Spock suite, Checkstyle, SpotBugs, JaCoCo gate

---

## 8. Risks & Mitigations

| # | Risk | Impact | Mitigation |
|---|---|---|---|
| R1 | OSV lacks class/method data for Maven (A4) | Verdicts coarser than plan.md implies | Artifact-level default + mapping file + explicit README caveat; M7 pointer analysis for precision |
| R2 | SootUp memory blowup on large classpaths | Analyzer OOMs in CI | Classpath scoped to SBOM-resolved jars (A7); memory-guard error with `-Xmx` hint; `--cha` cheaper fallback; per-jar skip on parse failure (warn, continue) |
| R3 | Reflection / dynamic dispatch (Spring wiring, SPI) | False UNREACHABLE (dangerous direction) | RTA from *all* detected entry points incl. framework handlers; CHA comparison available; report prints entry-point list for audit; M7 IFDS precision mode |
| R4 | SootUp next major (4.x) lands mid-project | API churn | Pin 3.0.1; isolation in `SootUpSetup` (single file owns SootUp types) so upgrade = one-file diff |
| R5 | `ComparableVersion` semantics differ from OSV intent at boundaries | Off-by-one at `fixed` boundary | Boundary cases pinned in M2 tests with real records; document semantics in ADR 0015 |
| R6 | Shade plugin conflicts (signatures, module-info, service files) | Fat-JAR fails at runtime | Filters configured at M0; service files merged via `ServicesResourceTransformer` |
| R7 | Air-gapped envs can't reach GCS | No OSV data | `download-osv.sh` produces a zip; publish to Nexus/Artifactory as an ops step (documented, not coded); `--osv-dir` is the only contract |
| R8 | SootUp **silently parses zero classes** for bytecode versions it does not handle (verified 2026-10-05: 2.0.0 empty on v69; 3.0.1 empty on hand-crafted v70) | Silent false "no vulnerability" verdict when a target moves to newer bytecode | SootUp 3.0.1 (ceiling = Java 25, verified) + startup guard (A12: version probe + zero-classes check → exit 3); report records detected class-file version |

### External proposals — verdicts (investigated 2026-10-05)

| Proposal | Verdict | Where / why |
|---|---|---|
| 1A Auto-download of method signatures from OSV/GHAD | **Not applicable** | Empirically: **0 of 7,163** OSV Maven records carry method-level data — the schema (`package`/`ranges`/`versions`/`database_specific`) has no method field, and GHAD exposes no Maven method bindings. No public CVE→method dataset exists. Keep `vuln-mappings.json` (A4) + M7 pointer analysis for precision |
| 1A Quick-win classpath warning | **Applicable, adopted** | `onClasspath` report field + console NOTICE for UNREACHABLE-but-present artifacts (reflection/dynamic-dispatch caveat) — M4 T41 + M5 T51/T54 (A14). No method data required |
| 1B Framework/DI entry-point heuristics | **Applicable in bounded form, adopted** | Curated callback-interface list + `--callback-interfaces` (M3 T32, A13) — `JavaSootClass.getInterfaces()` verified in 3.0.1. The "all implementations" variant rejected: would inflate entry points and collapse RTA precision (false positives) |
| 2A Call-graph caching | **Partially applicable — deferred, re-scoped** | SootUp 3.0.1 caches are in-memory only; no CG serialization API. Full-CG disk cache rarely hits in CI (app classes change every commit). JAR-level SHA-256 parse cache is the useful slice → M7, **benchmark-gated** (A16, baseline recorded at M4) |
| 2B Parallel candidate analysis | **Deferred, cheap if ever needed** | `GraphBasedCallGraph` is not thread-safe in 3.0.1 → would require an immutable snapshot (safe by construction). Per-candidate path-finding is ms-scale today → M7, benchmark-gated (A16) |
| 3A Native Gradle/Maven plugins | **Applicable, M7+** | `checkReachability` / `reachability:check` wrapping the engine; **triggers the A10 module split** (`core`/`cli`/plugins); auto-wires SBOM + classpath tasks (M7) |
| 3B SBOM agnosticism (CycloneDX + SPDX) | **Applicable, cheap** | `SbomParser` interface + auto-detect now (M1 T13, A15); SPDX **JSON** in M7; SPDX XML out of v1 (XML dependency, marginal gain) |
| 4A OSV integrity & validation | **Applicable, reframed, adopted** | TLS already covers transit; real need = **snapshot pinning** (`osv-maven.sha256` manifest, `--osv-checksum`) + fail-safe parsing (warn+skip+count; zero valid → exit 3; skip the 113 `withdrawn` records) — M1 T61 + M2 T21b (A14) |

---

## 9. Definition of Done (v1)

1. Fat-JAR builds from a clean checkout via `./gradlew shadowJar` in < 5 min;
   starts in < 3 s (JVM).
2. On `examples/vulnerable-demo` (vulnerable pin): exit 1, JSON + JUnit XML
   reports with full call trace; on fixed pin: exit 0.
3. GH Actions workflow template and Jenkinsfile committed and demonstrated.
4. Full test suite + Checkstyle + SpotBugs green; coverage gates met.
5. Single ADR and README complete, including the precision caveat (R1) and the
   bytecode-version guard (A12/R8), with the guard tests in the suite.
6. Analyzer runs on Java 25 (CI uses JDK 25); a `--release 25` target fixture
   is analyzed successfully, and a v70 fixture fails loudly with exit 3.
7. Total planned effort: **~9–11 working days** (M0–M6); M7 separate.

---

### Corrections to `plan.md` (recorded in ADR 0001)
- **SootUp 3.0.1** — 3.x **is published on Maven Central** (verified on
  repo1.maven.org 2026-10-05; the Solr search index lags and still reports
  2.0.0). Supersedes any "wait for 3.x" caveat; raises the target-bytecode
  ceiling to Java 25 (A12).
- Build system: `plan.md` assumed Maven (shade plugin); this plan uses
  **Gradle 9.8.0 + Shadow 9.0.0-beta12** (A2, A10) — all other decisions
  (SootUp 2.0.0, Jackson, picocli, offline OSV) are unaffected, and
  `maven-artifact` is a library dependency, not a build coupling.
- CycloneDX plugin **2.9.1**, not 2.8.0.
- `--classpath=~/.m2/repository` replaced by resolved classpath file (A7/R2).
- OSV all.zip is ~10 MB and daily-refreshed — direct CI download is viable;
  corporate cache becomes optional.
- Step 4.1 "extract affected class and method signatures from the database
  records" is not generally possible for Maven — replaced by A4.
