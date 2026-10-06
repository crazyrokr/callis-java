package org.reachability.analyzer.osv;

/**
 * One OSV range event: {@code introduced}, {@code fixed} or
 * {@code last_affected} with its version.
 */
public record VersionEvent(String type, String version) {

    public static final String INTRODUCED = "introduced";
    public static final String FIXED = "fixed";
    public static final String LAST_AFFECTED = "last_affected";

    @Override
    public String toString() {
        return type + "=" + version;
    }
}
