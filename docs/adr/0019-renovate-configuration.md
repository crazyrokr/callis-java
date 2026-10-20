# ADR 0019 — Renovate configuration (automatic dependency-update PRs)

- **Status:** accepted (2026-10-10); amended: 429 follow-up (2026-10-10)
- **Related:** ADR 0001 (index), ADR 0015 (`osv-maven` exclusion), ADR 0011 (maven-plugin module, `maven-plugin/**` group)

## Decision

`renovate.json5` at the repo root (JSON5 so the exclusions carry their
rationale; linked to the official schema; verified offline via
`npx renovate --platform local --dry-run`, which parses the config,
resolves `config:base`, and extracts 63 deps from the tracked files).
`config:base` — PRs only, no automerge, no platform automigration:
every update is a reviewable PR gated by `./gradlew check` in CI.

Default managers cover the intended scope: `gradle` (the version
catalog — the single source of truth — is edited in place, so one PR
per pin; every module build script; `settings.gradle.kts`),
`gradleWrapper`, `maven` (`maven-plugin/pom.xml`), `mavenWrapper`,
`github-actions` (both workflows).

`packageRules`: one "maven plugin toolchain" group PR for
`maven-plugin/**` (pure build tooling, several pinned APIs);
`rebaseStalePrs: true` (default is false).

`ignorePaths` — the two deliberate exclusions: `examples/vulnerable-demo`
(the log4j 2.14.1 pin is deliberately vulnerable, T65's fail-by-design
test; an "update" would silently flip the red test green) and
`osv-maven` (the snapshot `scripts/download-osv.sh` downloads; A14
pins it via `osv-maven.sha256` — a data artifact, not a dependency).

Enabling the bot on the repo is the remaining manual GitHub step:
install the Renovate app (or bot) on the repository; it opens an
onboarding PR that confirms the config, then starts creating PRs.

## Amendments

- **2026-10-10:** Follow-up (first live run failed with HTTP 429s from
  repo.maven.apache.org): two causes, two fixes.
  (1) The coverage-gate specs in core/build.gradle.kts
  ("org.crazyrock.callis.<pkg>:LINE|BRANCH:<min>") match the
  group:artifact:version shape, so the gradle manager misparsed them as
  Maven artifacts — and maven-plugin/pom.xml's dependency on this repo's
  own `core` module is never published either; a packageRule disables
  both name forms (bare artifact and full coordinate), so every run
  saves 6 wasted metadata lookups that can only 404/429.
  (2) hostRules throttle for repo.maven.apache.org: the first cap
  (`concurrentRequestLimit: 2`) did not stop 429s on the legitimate
  lookups (sootup, groovy), so it is now fully serialized —
  `concurrentRequestLimit: 1` plus `maxRequestsPerSecond: 2` (a 500ms
  gap; a run's ~15 metadata lookups take ~8s instead of bursting).
  Both are v44 hostRule options consumed by the HTTP layer
  (util/http/rate-limits.js; the pre-v44 name is not in the schema).
  Also revalidated against Renovate 44.149: `config:base` no longer
  exists (the CLI migrates it to `config:recommended`, which pulls in
  opinionated extras — dependency dashboard, forced action
  replacements — this repo does not want), so the config extends no
  preset and relies on the conservative bare defaults; the deprecated
  `matchFiles`/`rebaseStalePrs` options became `matchFileNames`
  (rebase-when-behind is the default, so no rebase option is needed).
  Verified with `npx renovate --platform local --dry-run`: no
  config-validation errors, no forced migration, zero
  org/reachability lookups, all 60 real deps still extracted.
  (Pacing itself is not observable from a local dry run — nearly every
  lookup is an HTTP-cache hit — so the 429 verdict comes from the next
  live run; if it persists, the egress IP is throttled at the edge and
  the remaining levers are a `schedule` or running from own infra.)

  The same-day "two CI reds" record was split across decision ADRs: the
  SARIF logical-location dedup fix lives in ADR 0010, and the
  maven-plugin e2e fixture-rebuild fix lives in ADR 0011.
