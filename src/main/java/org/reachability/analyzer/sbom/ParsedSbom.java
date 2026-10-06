package org.reachability.analyzer.sbom;

import java.util.List;

/** Result of parsing one SBOM file. */
public final class ParsedSbom {

    private final String format;
    private final String specVersion;
    private final List<SbomComponent> components;
    private final List<String> warnings;

    public ParsedSbom(String format, String specVersion,
                      List<SbomComponent> components, List<String> warnings) {
        this.format = format;
        this.specVersion = specVersion;
        this.components = List.copyOf(components);
        this.warnings = List.copyOf(warnings);
    }

    public String getFormat() {
        return format;
    }

    public String getSpecVersion() {
        return specVersion;
    }

    public List<SbomComponent> getComponents() {
        return components;
    }

    public List<String> getWarnings() {
        return warnings;
    }
}
