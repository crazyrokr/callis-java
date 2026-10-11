# ADR 0021 — Compact object headers enabled for the analyzer

- **Status:** accepted (2026-10-11)
- **Related:** ADR 0001 (index), ADR 0013 (Java 25 runtime/bytecode ceiling)

## Decision

`-XX:+UseCompactObjectHeaders` (JEP 519 — JDK 25 product flag, off by
default; JEP 450 preview in JDK 24) is enabled at every place the analyzer
runs or is built:

- Fat-JAR invocations: the `reachability-check` workflow (the consumer
  template), the `build-analyzer` sanity step, the committed Jenkinsfile,
  and the README quick start.
- Native build: `:cli:nativeCompile` passes the flag to the native-image
  compiler JVM via `BuildNativeImageTask.appendJvmArgs`.

Rationale (measured 2026-10-11, Temurin 25.0.3, 8 cores / 16 GB,
`-Xint` where object layout was isolated): object-heavy live sets shrink
~15–17% of heap and RSS (20M small objects: 921→769 MB heap,
1160→989 MB RSS; 50M: 2292→1911 MB, 2874→2373 MB — matching JEP 450's
10–20% claim), while array-dominated workloads (the committed demo target,
the Gradle/Maven builds, a full Kafka compile) show no measurable
difference, and no slowdown was observed in controlled A/B runs. The flag
is safe to hard-wire because the Fat-JAR already requires JDK 25
(ADR 0013), where it is a final product flag.

## Consequences

- On the demo target the flag saves nothing measurable; it pays off on
  consumer targets with object-heavy classpath/SBOM data.
- The flag does not change the native image's own layout or runtime
  memory: the binary is AOT, so the flag only trims the native-image
  compiler's heap at build time.
- On JDK 24 the flag exists only as the JEP 450 preview (experimental
  unlock required); on JDK 23 or earlier it does not exist. The Fat-JAR's
  Java 25 bytecode (ADR 0013) makes both cases unreachable in practice.
