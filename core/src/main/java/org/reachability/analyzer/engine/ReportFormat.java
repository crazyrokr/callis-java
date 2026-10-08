package org.reachability.analyzer.engine;

/** A9: the report formats the engine writes, with their file suffixes. */
public enum ReportFormat {
    JSON(".json"),
    JUNITXML(".junit.xml");

    private final String suffix;

    ReportFormat(String suffix) {
        this.suffix = suffix;
    }

    public String suffix() {
        return suffix;
    }
}
