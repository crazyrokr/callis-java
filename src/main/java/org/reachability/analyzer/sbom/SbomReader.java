package org.reachability.analyzer.sbom;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Reads an SBOM file and routes it to the matching {@link SbomParser} (A15):
 * CycloneDX via {@code bomFormat}, SPDX via {@code spdxVersion} (SPDX JSON
 * lands in M7). An unrecognized format is an explicit {@link SbomFormatException},
 * never a crash.
 */
public final class SbomReader {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final List<SbomParser> PARSERS = List.of(new CycloneDxParser());

    private SbomReader() {
    }

    public static ParsedSbom parse(Path file) throws IOException, SbomFormatException {
        JsonNode root = MAPPER.readTree(file.toFile());
        if (root == null || !root.isObject()) {
            throw new SbomFormatException("SBOM file is not a JSON object: " + file);
        }
        for (SbomParser parser : PARSERS) {
            if (parser.canParse(root)) {
                return parser.parse(root);
            }
        }
        throw unrecognized(root);
    }

    private static SbomFormatException unrecognized(JsonNode root) {
        if (root.has("spdxVersion")) {
            return new SbomFormatException("SPDX SBOM detected (spdxVersion="
                    + root.path("spdxVersion").asText() + "); SPDX JSON support is planned (M7)");
        }
        if (root.has("bomFormat")) {
            return new SbomFormatException("unrecognized bomFormat '"
                    + root.path("bomFormat").asText() + "'");
        }
        return new SbomFormatException("unrecognized SBOM format: neither bomFormat "
                + "nor spdxVersion is present");
    }
}
