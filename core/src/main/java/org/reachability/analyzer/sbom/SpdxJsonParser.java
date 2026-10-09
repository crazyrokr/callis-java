package org.reachability.analyzer.sbom;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;

/**
 * SPDX 2.x JSON parser (A15, M7c). Reads the top-level {@code packages}
 * array into {@link SbomComponent}s: the name from {@code name}, the
 * version from {@code versionInfo}, the purl from the {@code purl}-typed
 * entry of {@code externalRefs}. Packages without a usable maven purl are
 * skipped with a warning — the same contract as {@link CycloneDxParser},
 * since OSV Maven records can only match maven coordinates.
 *
 * <p>{@code canParse} accepts only the {@code SPDX-2.x} versions; an
 * SPDX 3.x document is routed to the reader's explicit
 * {@link SbomFormatException} instead (3.x is not supported).
 */
public final class SpdxJsonParser implements SbomParser {

    @Override
    public String formatName() {
        return "SPDX";
    }

    @Override
    public boolean canParse(JsonNode root) {
        return root.isObject()
                && root.path("spdxVersion").asText("").startsWith("SPDX-2");
    }

    @Override
    public ParsedSbom parse(JsonNode root) throws SbomFormatException {
        String spdxVersion = root.path("spdxVersion").asText(null);
        List<String> warnings = new ArrayList<>();
        List<SbomComponent> components = new ArrayList<>();
        JsonNode packages = root.path("packages");
        if (packages.isArray()) {
            for (JsonNode pkg : packages) {
                collectPackage(pkg, components, warnings);
            }
        }
        return new ParsedSbom(formatName(), spdxVersion, components, warnings);
    }

    private void collectPackage(JsonNode pkg, List<SbomComponent> out, List<String> warnings) {
        String name = pkg.path("name").asText(null);
        if (name == null || name.isEmpty()) {
            warnings.add("package without a name was skipped");
            return;
        }
        String version = pkg.path("versionInfo").asText(null);
        String bomRef = pkg.path("SPDXRef-id").asText(null);

        String purlText = purlFromExternalRefs(pkg);
        if (purlText == null) {
            warnings.add("package " + name + " has no purl; skipped");
            return;
        }
        try {
            Purl purl = Purl.parse(purlText);
            if (purl.isMaven()) {
                out.add(new SbomComponent(name, version, purl, bomRef));
            } else {
                warnings.add("package " + name + " is not a maven purl; skipped");
            }
        } catch (IllegalArgumentException e) {
            warnings.add("package " + name + " has an unparseable purl '"
                    + purlText + "'; skipped");
        }
    }

    /** The {@code reference} of the first {@code externalRefs} entry with {@code referenceType "purl"}. */
    private static String purlFromExternalRefs(JsonNode pkg) {
        JsonNode refs = pkg.path("externalRefs");
        if (refs.isArray()) {
            for (JsonNode ref : refs) {
                if ("purl".equals(ref.path("referenceType").asText(null))) {
                    String reference = ref.path("reference").asText(null);
                    if (reference != null && !reference.isEmpty()) {
                        return reference;
                    }
                }
            }
        }
        return null;
    }
}
