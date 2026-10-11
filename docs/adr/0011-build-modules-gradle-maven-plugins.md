# ADR 0011 — A10: Single Gradle project for v1, multi-module from M7a

- **Status:** accepted (2026-10-05); amended: M7a (2026-10-07), M7e (2026-10-09), M8 (2026-10-10), M9 (2026-10-10), 2026-10-10 (maven-plugin e2e fixture rebuild)
- **Related:** ADR 0001 (index), ADR 0018 (coverage gate tooling in `tools:coveragetool`)

## Decision

v1 was a single Gradle project; split `core`/`cli` (and add Gradle/Maven
plugins) only when a library consumer appears — that split is the M7 trigger
for plugin work. **M7a (2026-10-07) realized the split:** root aggregator +
`core` (sbom/osv/analysis/report + the new `engine` package), `cli`
(picocli + shadow fat JAR), `tools:coveragetool`. `core:engine.AnalyzerEngine`
is the in-process seam the M7e plugins call — the whole M4/M5 pipeline plus
report generation behind `analyze(AnalysisRequest, output, formats, verbose,
DiagnosticSink)`, console I/O abstracted so the CLI and plugins surface the
same diagnostics with the same exit codes. **M7e (2026-10-09) realized both
plugin front ends:** `gradle-plugin` (in the Gradle multi-project,
`java-gradle-plugin` + TestKit) applies the `reachability { ... }` extension
and the `checkReachability` task (group `verification`, wired to the main
source set's output and the resolved runtime classpath) and calls the same
`AnalyzerEngine.analyze` in-process — engine exit 1 becomes a
`GradleException` (task failure), exit 2/3 a usage/analysis failure.
`maven-plugin/` is a **separate Maven build inside the Gradle repo**
(recorded deviation — `maven-plugin` packaging requires a Maven build; the
root `mvnw` 3.9.16 wrapper is committed): the `reachability:check` Mojo
(default phase `verify`, `requiresDependencyResolution = RUNTIME`) reads the
project's built classes and `getRuntimeClasspathElements()`, failing with
`MojoExecutionException` on exit 1/2/3. `:core` gained `maven-publish`
(local repository) so the Maven build depends on
`org.reachability:core:0.1.0-SNAPSHOT`. Two recorded plan simplifications:
the "auto-detect the CycloneDX plugin's output" idea was dropped — `bomFile`
is an explicit input (the user points it at their `bom.json`), keeping the
plugins build-tool-agnostic — and the maven-plugin's unit tests use plain
JUnit 5 instead of the JUnit-4-only maven-plugin-testing-harness.
**M8 (2026-10-10) hardened the Gradle front end:** `checkReachability` is
`@CacheableTask` with content-sensitive inputs — the main classes directory,
the `@Classpath` runtime classpath, and the SBOM/OSV/mappings *content*
(path strings alone would miss in-place edits) — plus declared outputs
(reports + `reachability-cp.txt`), so unchanged content is up-to-date and
the build cache restores the run for identical content in a new project
directory. M8 recorded that Gradle 9.8 removed `Project.getWorkers()` and
exposes no public `WorkerExecutor` accessor (the worker types are exported
but unreachable without internal APIs; even the built-in java plugin does
not reference them), so the proposed out-of-process worker execution
appeared not implementable and the analysis stayed in the daemon.
**M9 (2026-10-10) corrected that:** no accessor is needed — the task
decorator *injects* the service: `@Inject public abstract WorkerExecutor
getWorkerExecutor()` on the task works (probed: the implementation
resolves from the daemon's worker jars, `processIsolation(...)` forks a
real JVM, the worker's log output is piped back into the build log, and
`await()` throws `WorkerExecutionException` with the worker's original
exception nested — the task unwraps it to keep its exact failure
messages). The analysis now runs in a **forked worker process**
(`maxHeapSize`, default `1g`) instead of the daemon, so a huge call graph
cannot starve the daemon. The 9.8 `WorkAction` parameter contract is
strict (all probed): the daemon instantiates the action's parameter type
via its object factory, so an interface must be property-shaped (a bare
setter without a getter fails the decorator); and configured parameters
reach the action **only** when it implements the internal
`org.gradle.workers.internal.ProvidesWorkResult` marker with an `@Inject
(WorkParameters, InstanceGenerator)` constructor — a plain action *runs
but silently receives nothing* (a deliberately failing plain action
passed the probe), so `ReachabilityWorkAction` implements the marker and
the reflection pin in `ReachabilityPluginSpec` holds it.

## Amendments

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

- **2026-10-09 (M7e):** Gradle + Maven plugin front ends (A10 amended in
  place).
  * `gradle-plugin/` module (java-library + groovy + java-gradle-plugin,
    `api(project(":core"))`, plugin id `org.reachability`):
    `ReachabilityPlugin` requires the java plugin (clear
    `IllegalStateException` — Gradle 9.8 removed
    `PluginManager.hasPlugin(Class)`, so the check uses the plugin id
    "java", which `java-library` applies transitively); a
    `ReachabilityExtension` (defaults: formats `json,junitxml`, RTA policy,
    no overrides); a `CheckReachabilityTask` (depends on `compileJava`;
    inputs = the main classes directory + the `runtimeClasspath`
    configuration written to `build/reachability-cp.txt`; reports to
    `build/reachability-report.*`; the engine's `DiagnosticSink` maps to
    the task logger; exit 1 ⇒ `GradleException`, 2/3 ⇒ usage/analysis
    failure).
  * Tests first (7): `ReachabilityPluginSpec` (ProjectBuilder: extension
    + task exist with the documented defaults; no-java-plugin ⇒ clear
    error — Gradle wraps plugin application in
    `PluginApplicationException`, so the assertion pins the cause;
    extension values reach the realized task's inputs) +
    `CheckReachabilityTaskFunctionalSpec` (Gradle TestKit, hermetic
    fixture projects against core's generated stublib.jar: vulnerable pin
    ⇒ task fails and `build/reachability-report.{json,junit.xml}` exist;
    `cha` ⇒ same verdict; empty OSV dir ⇒ success with "No vulnerability
    candidates"; missing `bomFile` ⇒ usage error).
  * `maven-plugin/` (separate Maven build; root `mvnw` 3.9.16 committed):
    `reachability:check` Mojo (default phase `verify`,
    `requiresDependencyResolution = RUNTIME`): app classes from the
    project's output directory, classpath from
    `MavenProject.getRuntimeClasspathElements()` (3.9.16 includes the
    project's own classes directory — the engine logs it as a harmless
    "unreadable jar" warning), `sbomFile`/`osvDir` parameters with clear
    `MojoExecutionException`s when absent, reports to
    `target/reachability-report.*`, exit 1/2/3 ⇒ `MojoExecutionException`.
    `:core` publishes `org.reachability:core:0.1.0-SNAPSHOT` to the local
    repository (`maven-publish`) and the plugin pom depends on it.
  * Maven 3.9.16 API drift hit while testing (recorded here, not in a
    separate ADR): the `org.apache.maven.plugins.annotations` package is a
    separate artifact (`org.apache.maven.plugin-tools:maven-plugin-
    annotations`, 3.16.0 in this timeline); `DefaultArtifact`'s
    constructor no longer takes a `File` (7-arg constructor +
    `setFile`, and the handler must opt in with
    `setAddedToClasspath(true)` — the 1-arg `DefaultArtifactHandler`
    constructor leaves it `false`, silently excluding the artifact from
    `getRuntimeClasspathElements()`); `MavenProject.addArtifact` is gone
    (`getArtifacts().add`). Unit tests are plain JUnit 5 (5.14.4, surefire
    3.6.0) instead of the JUnit-4-only maven-plugin-testing-harness
    (recorded deviation).
  * Gradle 9.8 API drift hit in the plugin (also recorded here):
    `ProjectLayout` moved to `org.gradle.api.file`;
    `getBuildDirectory()` is a `DirectoryProperty`;
    `SourceSetOutput.getClassesDirs()` returns a `FileCollection`;
    `hasPlugin(Class)` removed; and Kotlin DSL: the `maven-publish`
    plugin id needs backticks, `create<MavenPublication> { }` is the
    generic form, and `components` is accessed via `getByName("java")`.
  * Suite total 413 (core 328 + cli 47 + coveragetool 31 + gradle-plugin 7),
    all green under `check --rerun-tasks`; the maven-plugin's 4 JUnit 5
    tests run under `./mvnw -f maven-plugin/pom.xml install`. Coverage
    gates unchanged (the plugin code is new modules outside the gated
    core packages); Checkstyle clean on the new Java.
  * `scripts/maven-plugin-e2e.sh`: publish core → install the plugin →
    demo `mvn package -Dlog4j.version=…` + direct goal invocation (the
    demo pom stays clean; relative `-D` paths resolve against the project
    basedir, so the script passes absolute paths): 2.14.1 fails with
    `reachability-report.{json,junit.xml}` on disk, 2.25.5 passes. Runs
    as the `maven-plugin` job in `build-analyzer.yml`.
  * README: status line M7e; module layout mentions both plugin modules;
    new "Build plugins (M7e, A10)" section (Gradle snippet, Maven goal
    snippet, E2E + CI job note).

- **2026-10-10 (M8):** Gradle plugin hardening — cacheable task with
  content-sensitive inputs (A10 amended in place), from a review of four
  user proposals. Verdicts: the `@CacheableTask`/`@PathSensitive` proposal
  is applicable and exposed gaps beyond it (below); the out-of-process
  Worker API proposal is **not implementable in 9.8** (see the A10
  note — no public `WorkerExecutor` accessor), so the analysis stays
  in-daemon with the `org.gradle.jvmargs` guidance; SARIF output was
  already done in M7c; the "infer an SBOM from the classpath" proposal is
  **deferred** (a classpath-inferred SBOM silently drops shaded,
  relocated, or non-Maven jars → false "no reachable vulnerabilities"
  from a security gate; it would also change the pinned exit-2 contract
  for a missing `--sbom` and add cyclonedx-core-java under core's
  100% line-coverage gate — if ever pursued: strict opt-in, loud per-jar
  warnings, `sbomSource` in report metadata).
  * `CheckReachabilityTask` (same file, amended): the pre-M8 gaps —
    `appClasses` was `@Internal` (not an input at all; `dependsOn`
    compileJava is ordering, not up-to-date data),
    `bomFile`/`osvDir`/`mappings` were `@Input` path *strings* (content
    edits invisible), and no declared outputs (not cacheable) — now:
    `@InputDirectory @PathSensitive(NONE)` app classes, `@Classpath`
    jars, `@Optional @PathSensitive(NONE)` content inputs
    (`RegularFileProperty`/`DirectoryProperty` — plain
    `Property<RegularFile>`/`Property<Directory>` members are not
    creatable in 9.8 — wired from the extension's path properties, blank
    = absent, resolved against the project directory), and
    `@OutputFiles` = the classpath file (non-empty classpath only) + the
    per-format reports. A zero-candidate run still deletes the previous
    reports (engine contract) and the task stays up-to-date afterwards —
    Gradle records per-file output state, absence included.
  * Relative `bomFile`/`osvDir`/`mappings` now resolve against the
    project directory and are lexically normalized (previously the
    engine saw them relative to the daemon's CWD — wrong under daemon
    reuse). Both the task and the plugin use `Path.of(...)` +
    `resolve` for it: **JDK 25.0.3's two-arg `File(parent, child)`
    constructor joins absolute children instead of replacing the parent**
    (`Path.resolve` kept the standard semantics — probed with a plain
    javac/java test), so the `File` form is a latent bug in this
    timeline.
  * Tests first (5 new; 12 in the module): four TestKit pins — app class
    edited ⇒ re-run + `REACHABLE` flip; an OSV record dropped into the
    directory in place ⇒ re-run + candidate analyzed; a local SBOM copy
    edited (affected version gone) ⇒ re-run + "No vulnerability
    candidates"; and `--build-cache`: identical content in a *new*
    project directory ⇒ `FROM_CACHE` with `reachability-cp.txt` and the
    report restored — plus a reflection pin of the new annotations
    (single-value `PathSensitive.value()` in 9.8). All four up-to-date
    pins fail against the pre-M8 task (the stale `UP_TO_DATE` runs),
    which is the regression proof.
  * Gradle 9.8 API drift hit while implementing (recorded here):
    `Project.getWorkers()` is gone with no public replacement — the
    `org.gradle.workers.*` types, incl. `WorkAction`/`WorkParameters`
    (exported only by `gradle-public-api-legacy-9.8.0.jar`, and they do
    resolve from `gradleApi()`), exist but no API class exposes a
    `WorkerExecutor`, and the built-in java plugin references no worker
    API either; `Task.getOutputs()` is a reserved name (the accessor is
    `getWrittenFiles()`); `Project.provider` takes a `Callable`;
    `WorkAction` is `execute()` + `getParameters()` only.
  * Suite total 418 (core 328 + cli 47 + coveragetool 31 + gradle-plugin
    12), all green under `check --rerun-tasks`; maven-plugin 4/4 under
    `./mvnw install` and the E2E script re-run green (demo 2.14.1 fails
    with reports on disk / 2.25.5 passes — the Maven front end is
    unchanged); coverage gates unchanged (plugin code is outside the
    gated core packages); Checkstyle clean on the amended Java.
  * README: the "Build plugins" section notes the cacheable,
    content-sensitive task (`UP_TO_DATE` on unchanged content,
    `FROM_CACHE` across directories) and the `org.gradle.jvmargs`
    guidance for huge graphs.

- **2026-10-10 (M9):** out-of-process worker execution for the Gradle
  task (A10 amended in place — the M8 "not implementable" record was
  wrong: `Project.getWorkers()` is gone, but the task decorator
  *injects* the `WorkerExecutor` via `@Inject`, which no public accessor
  is needed for).
  * Probes (throwaway task + TestKit spec, deleted afterwards) settled
    the 9.8 contract: `@Inject public abstract WorkerExecutor
    getWorkerExecutor()` is injected (implementation from
    `lib/plugins/gradle-workers-9.8.0.jar`);
    `processIsolation(spec -> spec.getForkOptions().setMaxHeapSize(...))`
    forks a real JVM (daemon and worker pids differ; the worker's stdout
    is piped back into the build log at default console level);
    `submit(actionClass, params -> ...)` — the daemon instantiates the
    action's parameter type via its object factory (an interface must be
    property-shaped: a bare setter without a getter fails with
    "Cannot have abstract method"), and configured parameters reach the
    action **only** when it implements the internal
    `org.gradle.workers.internal.ProvidesWorkResult` marker (on the
    `gradleApi()` classpath in this build, so the plugin can implement
    it without exotic dependencies) with an `@Inject (WorkParameters,
    InstanceGenerator)` constructor — a plain action runs but silently
    receives *nothing* (probed: a deliberately failing plain action
    passed the build); `await()` throws `WorkerExecutionException`
    (a RuntimeException, multi-cause) with the worker's original
    exception nested in the cause chain.
  * `ReachabilityWorkAction` (new): all request data as strings/lists
    (nothing live crosses the process boundary); implements
    `ProvidesWorkResult` + the `@Inject` 2-arg constructor; rebuilds the
    `AnalysisRequest`, runs `AnalyzerEngine.analyze` in the worker with a
    `Logging`-based sink (out → lifecycle, err → error), announces its
    own pid ("reachability: analysis runs in process N"), and rethrows
    the task's exact messages (exit 1 → "reachable vulnerabilities found
    - see …", 2/3 → "reachability analysis failed (exit N)").
  * `CheckReachabilityTask`: gains `@Inject getWorkerExecutor()` and
    `@Internal getMaxHeapSize()` (a resource setting, not a verdict
    input); `check()` keeps the three in-daemon pre-checks, then submits
    the action to `processIsolation` with the configured max heap and
    unwraps `WorkerExecutionException` to the task's own
    `GradleException` (first non-wrapping GradleException in the cause /
    suppressed chain). The pre-M8/M7e functional tests pass
    byte-identical — their output assertions are the
    behavioral-equivalence proof (worker log lines surface at default
    console level) — and the `FROM_CACHE` pin still holds, so the task
    stays cacheable.
  * `ReachabilityExtension` gains `maxHeapSize` (convention `1g`); the
    plugin wires it to the task.
  * Tests first (4 new; 16 in the module): TestKit — the analysis runs
    in a forked worker process (the worker's pid announcement is the
    pin; red against the in-daemon code) and a vulnerable run's failure
    names the report files (pins the unwrap); `ReachabilityPluginSpec` —
    `maxHeapSize` default + propagation, and a reflection pin that the
    action carries `ProvidesWorkResult` + the `@Inject` constructor.
  * Suite total 422 (core 328 + cli 47 + coveragetool 31 + gradle-plugin
    16), all green under `check --rerun-tasks` (one 121-char line fixed
    by Checkstyle); maven-plugin 4/4 under `./mvnw install` and the E2E
    script re-run green (demo 2.14.1 fails with reports on disk /
    2.25.5 passes — the Maven front end is unchanged); coverage gates
    unchanged; Checkstyle clean.
  * README: status line M9; the "Build plugins" section now notes the
    forked worker process and the `maxHeapSize` convention (the
    `org.gradle.jvmargs` guidance is superseded — the worker's own heap
    bounds the graph, not the daemon's).

- **2026-10-10:** the `build-analyzer` maven-plugin job: `./mvnw install`
  failed in a fresh checkout — ReachabilityCheckMojoTest compiles its
  fixture app against ../core/.../mini-app/stublib.jar, which is
  generated (gitignored) and absent until a core generator runs; the
  e2e script's first step now also runs `:core:stublibJar`. Verified by
  deleting every generated fixture (jar, mini-app classes, bytecode
  probes, core/build) and running the script: regenerated, plugin tests
  4/4, demo 2.14.1 red with reports / 2.25.5 green. (The same-day SARIF
  CI red of the record lives in ADR 0010.)

- **2026-10-11:** the `maven-plugin` CI job failed again on a fresh
  checkout: the e2e script's demo runs point `-Dreachability.osvDir` at
  `osv-maven/`, which is gitignored and absent until
  `scripts/download-osv.sh` runs (the consumer template downloads it in a
  dedicated step; the job only ran the script) — both pins died with exit 2
  and no reports. The script now downloads the snapshot when the directory
  is missing (a local copy is reused as-is, mirroring
  `reachability-check.yml`). Verified by deleting the local snapshot and
  re-running: the download happened, and demo 2.14.1 fails with reports /
  2.25.5 passes.
