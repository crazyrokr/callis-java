package org.reachability.analyzer.sbom;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * One SBOM format (A15). Each new format is one implementation plus one
 * registration in {@link SbomReader} - CycloneDX now, SPDX JSON in M7.
 */
public interface SbomParser {

    /** Name of the SBOM format, e.g. "CycloneDX". */
    String formatName();

    /** Whether this parser can handle the given document root. */
    boolean canParse(JsonNode root);

    ParsedSbom parse(JsonNode root) throws SbomFormatException;
}
