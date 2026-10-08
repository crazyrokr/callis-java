package org.reachability.analyzer.sbom;

/**
 * The SBOM file is not in a supported format (or in a supported format with an
 * unsupported spec version). The CLI reports this as a usage error (exit 2) -
 * an explicit error, never a crash.
 */
public class SbomFormatException extends Exception {

    public SbomFormatException(String message) {
        super(message);
    }
}
