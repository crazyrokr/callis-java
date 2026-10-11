# ADR 0005 — A4: Artifact-level reachability default; class/method-level via mapping file

- **Status:** accepted (2026-10-05); amended: M4 verification (2026-10-07)
- **Related:** ADR 0001 (index), ADR 0015 (OSV snapshot pinning + classpath NOTICE), ADR 0017 (benchmark baseline)

## Context

**Capability boundary (drives A4):** OSV Maven records carry package-level
`affected`/`ranges` data only — 0 of the 7,163 records in the current dump carry
class/method signatures (verified 2026-10-05). Reachability is therefore
artifact-level by default, with an optional `vuln-mappings.json` escape hatch for
critical CVEs.

## Decision

OSV has no method data for Maven (capability boundary above). The default verdict
must not overpromise precision; `vuln-mappings.json` (vuln id → classes/methods)
gives the escape hatch. Documented as the #1 precision limitation (R1) in the README.

## Amendments

- **2026-10-07 (M4 verification):** verdict model (T41/T44). A candidate
  matches at **METHOD level** when its mapping names methods that resolve
  in the parsed view (reachability = the resolved signature is in the call
  graph); otherwise it falls back to **ARTIFACT level** (any class of the
  artifact's jar with a method in the graph — constructors excluded:
  instantiating the artifact is not use of a vulnerable method). States:
  `REACHABLE`, `UNREACHABLE`, `NO_CLASS_INFO`. **A14 `onClasspath`**:
  artifact present in the parsed view but nothing reachable → `UNREACHABLE`
  + console `NOTICE ... artifact present in classpath - possible reflection
  or dynamic dispatch risk`; artifact absent from the classpath entirely →
  `NO_CLASS_INFO` + `NOTICE ... artifact not on classpath - no class info`
  (see ADR 0015 for the A14 record). Any `REACHABLE` ⇒ exit 1 with a
  `CRITICAL` line + the call path; all unreachable ⇒ exit 0; zero
  candidates short-circuits before the analysis (exit 0).

- **2026-10-07 (M4 verification):** the optional `--mappings
  vuln-mappings.json` (T42) is a strict object
  `{"VULN-ID": [{"class": "...", "method": "...", "descriptor": "(...)"?}]}`,
  validated at startup before any analysis (malformed ⇒ exit 2, unreadable
  ⇒ exit 2). `descriptor` is a source-style parameter list that narrows the
  match to one overload (matched against the sub-signature suffix). Mapping
  ids that match no candidate are warned, never fatal; an empty target list
  falls back to the artifact level. Artifact jars are indexed by file name
  (`name[-version]` stem → binary class names); a version-suffixed jar
  matching the SBOM version is preferred, with fallback to the union of all
  same-named jars; unreadable/corrupt jars warn and are skipped (T34
  skip-and-continue).

- **2026-10-07 (M4 verification):** `fixtures/mini-app` grew to 49 app
  classes (`VulnCaller`, `VulnCaller2`, `VulnService` for the positive chain
  and the lexicographic tie); new fixtures `bom-mini.json`,
  `osv-mini/VULN-POS.json`, `mappings/{valid,malformed,malformed-entry}.json`.
  The A16 performance baseline measured on this fixture lives in ADR 0017.
