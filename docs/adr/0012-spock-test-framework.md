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
