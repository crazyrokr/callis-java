# ADR 0008 — A7: Classpath scope = resolved dependency set (not `~/.m2/repository`)

- **Status:** accepted (2026-10-05)
- **Related:** ADR 0001 (index), ADR 0011 (Gradle/Maven plugin front ends resolve the runtime classpath)

## Decision

For a Maven target: `mvn dependency:build-classpath -Dmdep.outputFile=cp.txt`;
for Gradle: a small custom task writing `cp.txt`. These commands run in the
*analyzed* project only. A GBs-sized, jar-irrelevant `~/.m2/repository` classpath
would slow the call graph down and is a precision hazard (R2).
