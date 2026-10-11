# ADR 0010 — A9: Reports: JSON + JUnit XML + SARIF 2.1.0

- **Status:** accepted (2026-10-05); amended: M5 verification (2026-10-07), M6 verification (2026-10-07), M7c (2026-10-09), 2026-10-10 (SARIF logical-location dedup), 2026-10-11 (SARIF code-scanning locations)
- **Related:** ADR 0001 (index), ADR 0015 (SBOM formats), ADR 0018 (coverage gates)

## Decision

Per plan Phase 5. One `<testcase>` per vulnerability; REACHABLE ⇒ `<failure>`
with the call trace, UNREACHABLE ⇒ pass (badges fail exactly when the pipeline
must fail). **M7c (2026-10-09) added SARIF 2.1.0** as the third format
(`--format sarif` → `<output>.sarif`): a findings document for CI
code-scanning UIs — one rule per distinct candidate id (the OSV record's
summary as `fullDescription`), a `results[]` entry per REACHABLE
vulnerability only (level `error`, the call trace as the message, the
component purl in the result `properties`, a `physicalLocation` at the
analyzed SBOM file, one logical location per path hop — the purl is not a
location URI, because GitHub code-scanning post-processing requires a
physical location per result and rejects artifact-location URIs whose scheme
does not match the checkout (a `pkg:` purl fails it; verified 2026-10-11)).
UNREACHABLE candidates stay out of the findings document by design — the JUnit
XML carries the full verdicts. The OSV `summary` also moved into the JSON
report's per-entry fields (M7c), so the evidence trail is shared across
formats.

## Amendments

- **2026-10-07 (M5 verification):** report model (T51). `AnalysisReport` is
  run metadata (tool version, CG builder, entry-point count, CG
  node/call counts, duration, detected target bytecode major, OSV snapshot
  sha256, OSV parse-skip count) plus one entry per candidate: id, component
  **purl** (the SBOM purl verbatim, qualifiers included — e.g.
  `…log4j-core@2.14.1?type=jar`), `REACHABLE|UNREACHABLE` (the
  NO_CLASS_INFO state reports UNREACHABLE with onClasspath=false),
  onClasspath, `severity`, `affectedRange`, `path[]`. Severity (T51) comes
  from the OSV top-level `severity` array as `TYPE` or `TYPE: score`
  strings, falling back to `database_specific.severity` (e.g. `CRITICAL`);
  both parses are **lenient** — severity is metadata, malformed entries are
  skipped, never record-rejecting (contrast the strict ADR-0001 M2 core
  fields). `affectedRange` is the matcher's evidence joined
  (`range#0 (introduced=0, fixed=2.0)` / `versions`). `OsvRecord` gained a
  `severities` field and `VulnerabilityCandidate` gained `purl` +
  `severities` (one candidate per (record, component), so the record's
  severity flows to the candidate).

- **2026-10-07 (M5 verification):** writers (T52/T53). `JsonReportWriter`
  serializes via Jackson `ObjectNode` — key order is the model's
  declaration order (insertion order), so output is byte-stable; the
  committed golden `fixtures/reports/reachability-report.golden.json` is
  re-recorded from the writer's own output (Jackson 2.22
  `DefaultPrettyPrinter` renders arrays inline, `[ { … } ]`). Absent
  optional metadata (bytecode major, OSV sha256) serializes as JSON `null`.
  `JUnitXmlReportWriter` emits one `<testsuite name="reachability">` and
  one `<testcase name="&lt;id&gt; &lt;purl&gt;">` per candidate:
  REACHABLE ⇒ `<failure message="reachable">` with the call trace in the
  body; UNREACHABLE ⇒ pass with a `<skipped>` note (onClasspath ⇒
  "artifact present in classpath … possible reflection/dynamic dispatch
  risk", A14; otherwise ⇒ "artifact not on classpath — no class info").
  **The suite fails exactly when the pipeline must fail (exit 1)** —
  `failures` equals the reachable count, so CI badges stay honest. All five
  XML specials are escaped (pinned: `& < > " '` round-trip through a DOM
  parse). Golden `…golden.xml` committed; both writers at
  **LINE 87/87 = 1.0** (gate active from M5).

- **2026-10-07 (M5 verification):** console + CLI (T54). The M4
  CRITICAL/NOTICE lines are kept; a summary table (id, component, verdict,
  **path head** only) is added so the console never duplicates the full
  report. `--verbose` names the written files and the duration.
  `osv-mini/VULN-POS.json` gained a `severity` array so the pipeline report
  carries real severity end-to-end. (The exit-code half of the same M5
  record lives in ADR 0009; its coverage numbers in ADR 0018.)

- **2026-10-07 (M6 verification):** stale-report deletion. A run that ends
  before report generation (zero candidates, analysis failure) used to leave
  a previous run's `reachability-report.*` behind — the CLI now deletes
  existing report files at analysis start (warns, does not fail, when a
  delete is impossible). Regression: CliSpec pre-creates reports, runs a
  zero-candidate pipeline into the same base name, and asserts both are gone
  (exit 0).

- **2026-10-09 (M7c):** SARIF findings output (A9 amended in place).
  * `report/SarifReportWriter` (SARIF 2.1.0, Jackson ObjectNode): one rule
    per distinct candidate id (deduped — a single OSV record can hit
    several components; OSV `summary` as `fullDescription`, first severity
    string as `properties.severity` when present), a `results[]` entry per
    REACHABLE vulnerability only (level `error`, the call trace as the
    message, the component purl as the artifact location, one logical
    location per path hop). New `ReportFormat.SARIF(".sarif")`; the engine
    dispatch and the CLI `--format` token `sarif` join json/junitxml.
  * The OSV record `summary` moved into `AnalysisReport.VulnerabilityEntry`
    (never null — the OSV record model defaults to "") and therefore into
    the JSON report as a per-entry field (golden file updated; key order
    pinned after `onClasspath`), so all three formats carry the same
    evidence.
  * `reachability-check.yml` now requests `--format=json,junitxml,sarif`,
    uploads the SARIF with the reports, and adds a
    `github/code-scanning/upload-sarif` step (`continue-on-error`: the
    living demo job's fail-by-design semantics stay on the final step even
    on runners without the action).
  * Tests first: `SarifReportWriterSpec` (5 — golden byte equality,
    field-for-field structure, id dedup with both results kept, empty
    report, non-writable destination), `CliSpec` 43 → 45 (sarif-only
    format, all-three formats, the rewritten `--dry-run-sbom` success /
    error pair), `AnalyzerEngineSpec` 10 → 11. Suite total 404 (core 328 +
    cli 45 + coveragetool 31), all green. (The SPDX 2.x SBOM input half of
    the same M7c record lives in ADR 0016.)
  * E2E demo (log4j 2.14.1, 2026-10-09): `--format=json,junitxml,sarif`
    exits 1 with 8/8 REACHABLE as before; the 28 KB SARIF carries 8 rules
    and 8 `error` results whose ruleIds equal the JSON's REACHABLE ids
    exactly, with the OSV summaries, CVSS severities, component purls and
    per-hop logical locations. Coverage gates unchanged and passing (sbom
    192/192, report 152/152 LINE 1.0); SpotBugs/Checkstyle clean.
  * README: `--format` reference line, quick start and the pipeline line
    gained SARIF. (The new "SBOM formats (A15)" README section lives with
    the SPDX half in ADR 0016.)

- **2026-10-10:** the `reachability-check` SARIF upload was rejected —
  "logicalLocations contains duplicate item" (results 1-7 of the log4j
  2.14.1 run). Root cause: the demo's trace visits two distinct methods that
  render to the same display name (log4j 2.14.1's static
  `LoggerConfig#log(LoggerConfig, LogEvent)` helper and the instance
  `LoggerConfig#log(LogEvent)` — a bridge-style overload pair), and
  SarifReportWriter emitted one logical location per hop by name, so the
  duplicated item failed the upload action's validation. Fix:
  `resultsNode` dedups logical locations (order-preserving, LinkedHashSet)
  while the result message keeps the full trace; new SarifReportWriterSpec
  test (repeated-hop trace: message keeps the duplicate, the location list
  drops it). Core suite 328 → 329; end-to-end: the regenerated demo SARIF
  has 8 results, 0 duplicate logicalLocations. (The same-day maven-plugin
  CI red of the record lives in ADR 0011.)

- **2026-10-11:** the `reachability-check` SARIF upload was *accepted* but
  GitHub code-scanning *processing* failed — "SARIF URI scheme `pkg` did not
  match the checkout URI scheme `file`" (all 8 results of the log4j 2.14.1
  run). Root cause: the M7c design put the component purl in
  `physicalLocation.artifactLocation.uri`; the upload action post-processes
  locations against the checkout, and a purl is not a checkout path, so the
  whole document was rejected. Fix: `resultsNode` drops `physicalLocation`
  (the location keeps its deduped `logicalLocations` only) and carries the
  component purl in the result `properties` (`"purl": …`) instead — the
  evidence stays in the document, the purl is just no longer a URI claim.
  The golden file was re-recorded from the writer and the
  SarifReportWriterSpec pins the `properties.purl` location plus the absence
  of `physicalLocation`. End-to-end: the regenerated demo SARIF carries the
  8 results with purls in properties and no `pkg:` URI anywhere, so the
  upload processes.

- **2026-10-11 (second processing red):** the same-day fix above was
  insufficient — the upload was accepted again, but processing failed with
  `locationFromSarifResult: expected a physical location` (all 8 results):
  the post-processor also requires every result to carry a
  `physicalLocation`, and the location with only `logicalLocations` had
  none. The only checkout-scheme-safe anchor the report knows is the
  analyzed SBOM file. Fix: `AnalysisReport.ReportMetadata` gained a
  `sbomFile` field (the engine records the `--sbom` path as given; the JSON
  report serializes it — absent ⇒ `null` — and both report goldens were
  re-recorded); `SarifReportWriter` emits
  `physicalLocation.artifactLocation.uri` at that path (checkout-relative
  as given; absolute paths become `file://` URIs) while the purl stays in
  the result `properties`. SarifReportWriterSpec 6 → 8 (absolute SBOM path
  ⇒ `file://` URI; missing SBOM file ⇒ location without a physical
  location), JsonReportWriterSpec pins the new metadata key (round-trip key
  order, JSON-null edge); core suite 329 → 331 (total 409). End-to-end: the
  regenerated demo SARIF carries 8 results, each with a physical location
  at `examples/vulnerable-demo/target/bom.json`, the deduped logical
  locations, and no `pkg:` URI anywhere.
