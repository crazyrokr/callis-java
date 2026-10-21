package org.crazyrock.callis.analysis;

/**
 * The vuln-mappings file does not have the expected structure. The CLI maps
 * this to exit 2 (a broken invocation, not an analysis failure).
 */
public class VulnMappingFormatException extends RuntimeException {

    public VulnMappingFormatException(String message) {
        super(message);
    }
}
