package org.reachability.analyzer.sbom;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * CycloneDX JSON parser (A15). Reads the top-level {@code components} array
 * (including nested components) into {@link SbomComponent}s. Components without
 * a maven purl are skipped with a warning - OSV Maven records can only match
 * maven coordinates.
 */
public final class CycloneDxParser implements SbomParser {

    /**
     * Spec versions this parser accepts. The CycloneDX 2.9.1 maven plugin emits
     * 1.6; 1.4/1.5 remain accepted for older SBOMs. Anything else is an
     * explicit error, not a best-effort parse.
     */
    static final Set<String> SUPPORTED_SPEC_VERSIONS = Set.of("1.4", "1.5", "1.6");

    @Override
    public String formatName() {
        return "CycloneDX";
    }

    @Override
    public boolean canParse(JsonNode root) {
        return root.isObject()
                && root.path("bomFormat").asText("").equalsIgnoreCase(formatName());
    }

    @Override
    public ParsedSbom parse(JsonNode root) throws SbomFormatException {
        String specVersion = root.path("specVersion").asText(null);
        List<String> warnings = new ArrayList<>();
        if (specVersion == null) {
            warnings.add("bom.json has no specVersion field; parsed best-effort");
        } else if (!SUPPORTED_SPEC_VERSIONS.contains(specVersion)) {
            throw new SbomFormatException("unsupported CycloneDX specVersion '" + specVersion
                    + "'; supported: " + SUPPORTED_SPEC_VERSIONS);
        }

        List<SbomComponent> components = new ArrayList<>();
        collectComponents(root.path("components"), components, warnings);
        return new ParsedSbom(formatName(), specVersion, components, warnings);
    }

    private void collectComponents(JsonNode componentsNode, List<SbomComponent> out,
                                   List<String> warnings) {
        if (!componentsNode.isArray()) {
            return;
        }
        for (JsonNode component : componentsNode) {
            String name = component.path("name").asText(null);
            if (name == null || name.isEmpty()) {
                warnings.add("component without a name was skipped");
                continue;
            }
            String version = component.path("version").asText(null);
            String bomRef = component.path("bom-ref").asText(null);

            String purlText = component.path("purl").asText(null);
            if (purlText == null || purlText.isEmpty()) {
                warnings.add("component " + name + " has no purl; skipped");
            } else {
                Purl purl = parseOrWarn(purlText, name, warnings);
                if (purl != null && purl.isMaven()) {
                    out.add(new SbomComponent(name, version, purl, bomRef));
                } else if (purl != null) {
                    warnings.add("component " + name + " is not a maven purl; skipped");
                }
            }

            collectComponents(component.path("components"), out, warnings);
        }
    }

    private Purl parseOrWarn(String purlText, String name, List<String> warnings) {
        try {
            return Purl.parse(purlText);
        } catch (IllegalArgumentException e) {
            warnings.add("component " + name + " has an unparseable purl '"
                    + purlText + "'; skipped");
            return null;
        }
    }
}
