# ADR 0003 — A2: Fat-JAR via Shadow; GraalVM native-image from M7d

- **Status:** accepted (2026-10-05); amended: M0 verification (2026-10-05), M7d (2026-10-09)
- **Related:** ADR 0001 (index), ADR 0002 (SootUp backend)

## Decision

Instant-start CI was nice-to-have, not v1. **M7d (2026-10-09) realized the
native path**: `org.graalvm.buildtools.native` 1.1.14 on `:cli`
(`:cli:nativeCompile` under a GraalVM 25 JDK; `check` stays under Temurin and
never builds the binary) — `cli/build/native/nativeCompile/cli` (21.5 MB).
`--version` starts in **3–13 ms** (plan budget: < 500 ms) and the full demo
run produces verdict-identical reports (JSON identical modulo
`durationMillis`, SARIF byte-identical, JUnit XML identical modulo the
`time` attribute, stdout byte-identical).

Empirical reflect-config (the plan's "SootUp's reflective use may need
native-image reflect config" turned out to be **picocli, not SootUp**):
neither jackson-databind 2.22.3 nor picocli 4.7.7 ships native-image
metadata in this timeline, and the GraalVM reachability-metadata repository
(1.0.15, used by the plugin) has no picocli entry — without a config the
binary only saw the built-in `-h`/`-V` options. One
`cli/src/main/resources/META-INF/native-image/reachability-analyzer/
reflect-config.json` (the CLI class: `allDeclaredFields` + the two picocli
annotation types) fixed it; SootUp/ASM/Jackson needed none — Jackson only
uses the generic JsonNode tree model (no POJO binding) and SootUp loads
classes through its own source locators, not `Class.forName`.

## Amendments

- **2026-10-05 (M0 verification):** plan pin `Shadow 9.0.0-beta12` → **Shadow
  9.6.1** (9.0.0 GA and later stable 9.x releases exist on Central; T05 asked to
  re-check GA availability — done, latest stable preferred).

- **2026-10-09 (M7d):** GraalVM native-image binary (A2 amended in place).
  * `:cli` gains `org.graalvm.buildtools.native` 1.1.14 (catalog key
    `graalvm-native` — Gradle 9.8 generates its accessor hierarchically:
    `libs.plugins.graalvm.native`); the task is `nativeCompile` (1.1.x
    naming), run under `JAVA_HOME=<GraalVM 25.0.3-graal>` — `check` stays
    under Temurin and never builds the binary. Binary:
    `cli/build/native/nativeCompile/cli` (21.5 MB, statically linked).
  * Acceptance (plan A2), 2026-10-09: `--version` starts in 3–13 ms
    (budget < 500 ms); the full vulnerable-demo run under the native binary
    exits 1 with 8/8 REACHABLE and produces verdict-identical reports vs
    the fat JAR (JSON identical modulo `durationMillis`, SARIF
    byte-identical, JUnit XML identical modulo the `time` attribute,
    stdout byte-identical; stderr identical — the SLF4J NOP notice).
    Native wall time for the demo: 1.8 s.
  * Empirical reflect-config (recorded above in the amended A2): the only
    missing metadata was picocli's `@Option`/`@Command` annotations on the
    CLI class — one `reflect-config.json` in the main resources'
    native-image auto-discovery location; SootUp/ASM/Jackson needed none.
  * `build-analyzer.yml` gains the `native` job (GraalVM 25 runner via
    `graalvm/jdks/setup-jdk`, `:cli:nativeCompile`, `--version` sanity,
    artifact upload); the action is unverified in this environment — the
    job's failure mode on unsupported runners is a skipped/failed upload,
    not a masked analyzer failure.
  * Tests first for the new resource: `NativeImageConfigSpec` (cli) pins
    the reflect-config's location (native-image auto-discovery path on the
    main classpath) and its content (CLI class entry, `allDeclaredFields`,
    both picocli annotation types). Suite total 406 (core 328 + cli 47 +
    coveragetool 31), all green; `check` under Temurin unaffected by the
    plugin.
  * README: new "Native image (M7d)" section (build command, binary path,
    measured startup, CI job note).
