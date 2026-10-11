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
