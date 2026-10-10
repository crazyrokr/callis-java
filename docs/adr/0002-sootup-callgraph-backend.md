# ADR 0002 — A1: SootUp 3.0.1 over classic Soot / ASM-only

- **Status:** accepted (2026-10-05); amended: M0 verification (2026-10-05)
- **Related:** ADR 0001 (index), ADR 0006 (call-graph policies), ADR 0013 (target-bytecode ceiling)

## Decision

Modern API, Jimple IR, maintained; CHA + RTA call graphs out of the box.
`org.soot-oss` 3.0.1 modules are published on Maven Central (verified 2026-10-05 on
repo1.maven.org; the Solr search index lags and still shows 2.0.0). Parses
≤ Java 25 bytecode. All SootUp types are confined to `analysis/SootUpSetup.java`
so an upgrade is a one-file diff (R4).

## Amendments

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
