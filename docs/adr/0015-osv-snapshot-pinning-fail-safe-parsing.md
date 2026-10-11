# ADR 0015 — A14: OSV snapshot pinning + fail-safe parsing + classpath NOTICE

- **Status:** accepted (2026-10-05); amended: M2 verification (2026-10-06)
- **Related:** ADR 0001 (index), ADR 0004 (snapshot download script), ADR 0005 (verdict states incl. onClasspath NOTICE), ADR 0010 (reports carry the sha256 + skip count)

## Decision

TLS covers transit integrity; the enterprise need is reproducibility:
`download-osv.sh` writes an `osv-maven.sha256` pin, the analyzer records the sha256
in report metadata, optional `--osv-checksum` verifies. Robustness: malformed
records skipped with a count; **zero valid records → exit 3**; `withdrawn`
records (113 in the current dump) are never indexed. The report carries
`onClasspath` + a reflection/dynamic-dispatch NOTICE for UNREACHABLE-but-present
artifacts — closes the "quick win" without any method-data dependency.
(The M4 verdict states implementing the NOTICE — `UNREACHABLE`/`NO_CLASS_INFO` —
are recorded in ADR 0005.)

## Amendments

- **2026-10-06 (M2 verification):** OSV record parsing is **strict** — a
  record whose shape deviates from the OSV schema (non-object root, missing /
  non-text id, affected not a non-empty array, entry without a package name,
  range without an events array, event without exactly one of
  introduced/fixed/last_affected, non-text event version) throws
  `OsvFormatException`, which the repository converts to a warn + skip +
  count (T21b). Two invariants verified against the current dump: 0 of 7,163
  records are malformed, and 113 are `withdrawn` — withdrawn records are
  **never indexed** (counted separately, `indexedRecordCount =
  validRecordCount − withdrawnCount`).

- **2026-10-06 (M2 verification):** **name-key indexing** (refines A14): every
  affected entry is indexed under every name form of its package — the raw
  `group:artifact` name and its purl form `group/artifact` (5,471 of 5,674
  entries in the dump are `group:artifact`, 203 plain). A component purl
  queries under its `group:name` qualified name and its `group/name` form; a
  purl **without** a namespace queries its plain name only, so it never
  matches a group-qualified record of the same artifact name (false-positive
  guard, tested).

- **2026-10-06 (M2 verification):** **version-range semantics** (pure engine
  `VersionRangeMatcher`, Maven `ComparableVersion` ordering): `introduced`
  inclusive, `fixed` exclusive, `last_affected` inclusive; ranges OR; a range
  without events matches nothing (a security gate must not guess); the
  explicit `versions` list is exact string membership. A version **equal to
  `fixed` is not affected** (plan false-positive guard, tested: log4j-core
  2.15.0 → no candidate, 2.14.1 → candidate). The
  `database_specific.last_known_affected_version_range` hint is normalized
  only when the entry has no `fixed` event anywhere: `<= N` → inclusive
  `last_affected N`, `< N` → exclusive `fixed N` (the dump uses only those
  two shapes — 2,394 and 172 entries); an unparseable hint leaves the record
  unchanged.

- **2026-10-06 (M2 verification):** the **snapshot checksum** (A14) is the
  sha256 over the sorted `name + ":" + hexSha256(file) + "\n"` concatenation
  of all `*.json` files in the directory (order-independent, stable across
  re-extraction); `--osv-checksum <sha256>` verifies it and `--dry-run-match`
  prints the candidate table without bytecode analysis. A non-empty OSV
  directory yielding **zero valid records is the fail-safe** the CLI maps to
  exit 3 (A14/A8).
