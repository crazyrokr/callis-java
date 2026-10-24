# ADR 0012 — A11: Spock (Groovy 4) as the test framework

- **Status:** accepted (2026-10-05); amended: M0 verification (2026-10-05)
- **Related:** ADR 0001 (index)

## Decision

Spock's `given:/when:/then:` is the mandated test structure as a language
construct; built-in assertions replace AssertJ (one assertion style across the
codebase); `where:` data tables make the M2 edge-case matrix one table per case
family; `Mock()`/`Stub()` are built-in (no Mockito). Production code stays 100%
Java; Groovy lives only under `src/test/groovy`.

## Amendments

- **2026-10-05 (M0 verification):** plan pin `Spock 2.3-groovy-4.0` → **Spock
  2.4-groovy-4.0** (2.4 GA released; plan said "re-check at M0" — done). Groovy
  stays on the 4.0 line (4.0.32) per A11.
- **2026-10-23 (Groovy 6):** `spock` → **2.5-groovy-6.0**, `groovy` → **6.0.0**
  (renovate; ADR 0019). Two consequences for the `:gradle-plugin` tests:
  (1) Groovy 6 removed `org.codehaus.groovy.runtime.callsite` (including
  `CallSite`), which the Gradle 9.8.x API's meta-object layer
  (`MetaClassAdapter` → `CallInterceptorRegistry`) loads on any Groovy dynamic
  dispatch on a `DefaultProject` — so `ProjectBuilder`-based specs throw
  `NoClassDefFoundError` on a Groovy 6 test classpath. The project-level
  wiring assertions (extension defaults, the verification group, the
  no-java error, maxHeapSize, values reaching task inputs) now run through
  TestKit fixture builds — the same pattern tickonomics uses for its
  plugin specs — where each fixture carries a dumpWiring task that writes
  the live extension/task values to a file, so `ReachabilityPluginSpec`
  asserts the same values as the original in-project assertions (the
  fixture plumbing — build-script generation, TestKit runs, the dump read
  — lives in a `FixtureProject` test helper); the task/work-action
  contract pins stay in the spec itself (pure reflection, no project
  needed). (2) The Gradle API
  injects the distribution's embedded Groovy jars (4.0.33) into this project's
  classpaths outside dependency resolution, ahead of the resolved jars, so the
  test compile/runtime classpaths strip them and take the four 6.0.0 Groovy
  module jars the Gradle API actually references (`groovy-ant`,
  `groovy-json`, `groovy-templates`, `groovy-xml`) from the resolved BOM
  instead; the core `groovy` artifact pulls none of them in transitively and
  the other dist-bundled modules (astbuilder, datetime, dateutil, groovydoc,
  nio) are referenced by no class on the test classpath. No released Gradle embeds Groovy 6 (all 9.x
  embed 4.0.x), so upgrading the wrapper is not an option.
