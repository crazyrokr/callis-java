# ADR 0016 — A15: SBOM-format agnosticism via `SbomParser`

- **Status:** accepted (2026-10-05); amended: M7c (2026-10-09)
- **Related:** ADR 0001 (index), ADR 0010 (SARIF findings output, same M7c milestone)

## Decision

CycloneDX now (interface + auto-detect from `bomFormat` vs `spdxVersion`);
SPDX **2.x JSON** since M7c (auto-detect from `spdxVersion` starting with
`SPDX-2`); **SPDX 3.x is an explicit `SbomFormatException`** ("only SPDX 2.x
is supported"), never a best-effort parse; SPDX XML remains out of scope.
Enterprises split between the two formats; the interface makes each new format
one class.

## Amendments

- **2026-10-09 (M7c):** SPDX 2.x SBOM input (A15 amended in place).
  * `sbom/SpdxJsonParser` (A15): `packages[]` → `SbomComponent` (name,
    `versionInfo`, the `purl`-typed entry of `externalRefs`, `SPDXRef-id`
    as bom ref); packages without a usable maven purl are skipped with the
    CycloneDX warning contract. Registered in `SbomReader.PARSERS`;
    `canParse` accepts only `spdxVersion` starting with `SPDX-2`, so an
    SPDX 3.x document is an explicit `SbomFormatException` naming the
    version ("only SPDX 2.x is supported") instead of the old "planned (M7)"
    message.
  * Tests first: `SpdxJsonParserSpec` (16 — fixture parse, the `canParse`
    2.x/3.x boundary table, non-maven/unparseable/empty purl skips,
    multi-ref selection, name/version/empty-packages edges),
    `SbomReaderSpec` 6 → 8, `CliSpec` 43 → 45 (the rewritten
    `--dry-run-sbom` SPDX 2.x success / 3.x error pair). (The SARIF half of
    the same M7c test/E2E/README record lives in ADR 0010.)
  * README: new "SBOM formats (A15)" section (CycloneDX 1.4–1.6 +
    SPDX 2.x in, SPDX 3.x explicit error).
