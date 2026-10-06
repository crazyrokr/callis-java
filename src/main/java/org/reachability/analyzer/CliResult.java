package org.reachability.analyzer;

/**
 * Exit-code contract (A8). Single source for exit codes so no scattered System.exit:
 * 0 = no reachable vulnerabilities; 1 = at least one REACHABLE;
 * 2 = usage/config error; 3 = analysis/runtime failure.
 */
public enum CliResult {
    OK(0),
    REACHABLE_VULNERABILITIES(1),
    USAGE_ERROR(2),
    ANALYSIS_FAILURE(3);

    private final int exitCode;

    CliResult(int exitCode) {
        this.exitCode = exitCode;
    }

    public int exitCode() {
        return exitCode;
    }
}
