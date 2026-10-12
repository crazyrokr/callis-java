# ADR 0020 — GitHub Actions dependency and snapshot caching

- **Status:** accepted (2026-10-11)
- **Related:** ADR 0001 (index), ADR 0004 (offline OSV snapshot), ADR 0015 (snapshot pinning)

## Decision

Both workflows re-downloaded everything on every run (fresh checkouts have no
dependency caches). Caching was added without changing gate semantics:

- `reachability-check`: `setup-java cache: maven` (key = hash of `**/pom.xml`)
  for the demo's Maven build, plus `gradle/actions/setup-gradle` for the
  Fat-JAR build (Gradle 9.8 user-home and build-cache entries are shared
  repository-wide, so the `build-analyzer` job's `shadowJar` hits them).
- `build-analyzer` `maven-plugin` job: `setup-java cache: maven` for the
  e2e script's `./mvnw` builds (plugin install, demo packages).
- The gitignored OSV snapshot (ADR 0004) and the sha256 pin written next to
  it (ADR 0015) are cached together under `actions/cache` with the remote
  zip's `ETag` header as key: the ETag changes on every upstream re-upload,
  so a new snapshot invalidates the entry, and the script re-verifies the
  pin after download. The pin is restored with the directory because the
  workflow reads it (`--osv-checksum`) and the script writes it beside, not
  inside, the directory.
- `native` job: `setup-gradle cache-provider: external` — the
  `graalvm/setup-graalvm` action already caches the Gradle user home
  (`cache: "gradle"`); the setup-gradle docs advise against two mechanisms
  caching the same directory.

Cache keys follow the dependency manifests (Gradle scripts, pom.xml, remote
ETag), not sources: unchanged sources still hit every cache, and a changed
dependency declaration (or upstream snapshot) invalidates only the affected
entry.

## Rejected

- `hashFiles('osv-maven.sha256')` as the snapshot cache key: the pin is
  gitignored, so the hash is always empty, the key constant, and the first
  cached snapshot would be served forever after any upstream update.
- Committing the pin under a non-ignored name: this repository
  intentionally keeps the pin uncommitted (consumer repositories commit
  theirs, ADR 0015); the ETag key tracks the actual upstream state instead.
- A `prepare` job that warms the dependency cache before the parallel
  jobs: in steady state it adds a serialized step to every run (worse
  wall-clock), and on a cache miss the three jobs already download
  concurrently — 3× the bandwidth, but still one wall-clock pass. It
  would save bandwidth, never time, so it was rejected.

## Amendments

- **2026-10-12:** the `native` job now runs `setup-gradle`'s default
  **enhanced** state caching (⚡ in the job UI): `graalvm/setup-graalvm`
  no longer passes `cache: "gradle"` (the JDK install it performs is
  tool-cached regardless; the option only added a second, classic
  `actions/cache` save of the same directory) and the
  `cache-provider: external` override is dropped. The "one mechanism
  caches" rule above still holds — the mechanism is just ⚡ now. The
  key is build-file + JDK-version based, so the entry may be shared
  with the `build` job (both Java 25): safe, the dependency cache is
  JDK-agnostic and a concurrent save simply loses to the first.

- **2026-10-12:** the **Gradle build cache** is enabled
  (`org.gradle.caching=true` in `gradle.properties`): compile/test
  outputs land in the same enhanced-cached user home, so the three
  parallel jobs stop each re-compiling from scratch — `build` compiled
  core+cli+coveragetool for `check`, `native` re-compiled core+cli for
  `nativeCompile`, and `maven-plugin` compiled `:core` a third time for
  `publishToMavenLocal`. Keys are input- and toolchain-JDK-sensitive
  (Temurin and GraalVM entries stay separate); concurrent saves from
  the parallel jobs are first-save-wins. Measured locally
  (Temurin / GraalVM 25.0.3): `clean check` 54 s → **13 s (24 tasks
  FROM-CACHE, suite and coverage gate green)**; a repeated GraalVM
  `clean :cli:nativeCompile` runs the compiles FROM-CACHE and only
  re-runs the native-image step (~1.5–2 min — the job's new floor).
