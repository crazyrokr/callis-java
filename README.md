# reachability-analyzer

Answers one question in CI: **is this vulnerability in the SBOM actually
reachable from application code?**

Pipeline: `CycloneDX SBOM` + `local OSV database` → candidate vulnerabilities →
`SootUp` call graph (entry points → app bytecode + resolved library jars) →
REACHABLE / UNREACHABLE verdicts with call traces → JSON + JUnit XML reports.
Exit code `1` on any reachable vulnerability (fail the pipeline), `0` otherwise
(`2` = usage error, `3` = analysis failure).

Status: under construction — see `implementation-plan.md` for milestones.

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

## Quick start (once built)

```bash
./gradlew shadowJar
java -jar build/libs/reachability-analyzer-0.1.0-SNAPSHOT-all.jar --help
```

## Precision caveat

OSV Maven records carry **package-level** data only (no class/method
signatures — 0 of 7,163 records carry method data). Default verdicts are
artifact-level ("some class of the vulnerable artifact is reachable"); use
`--mappings=vuln-mappings.json` for class/method-level precision on critical
CVEs. See the ADR for details.

## Bytecode-version guard

SootUp 3.0.1 parses class files up to Java 25 (major 69) and **silently**
returns zero classes for anything newer. The analyzer probes the target's
max class-file version and exits `3` beyond the ceiling (regression fixtures
in `src/test/resources/fixtures/bytecode/`).

## License / origin

Greenfield project; see `docs/adr/0001-architecture.md` (single ADR) and
`implementation-plan.md`.
