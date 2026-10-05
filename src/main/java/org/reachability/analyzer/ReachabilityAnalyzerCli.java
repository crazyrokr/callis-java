package org.reachability.analyzer;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * CLI entry point. M0 skeleton: full options and the analysis pipeline are wired in M1-M6.
 */
@Command(
        name = "reachability-analyzer",
        version = "reachability-analyzer ${version}",
        mixinStandardHelpOptions = true,
        description = "Determines whether vulnerabilities listed in a CycloneDX SBOM are "
                + "reachable from application code, using a SootUp call graph."
)
public final class ReachabilityAnalyzerCli implements Runnable {

    private static final String VERSION = "0.1.0-SNAPSHOT";

    public static void main(String[] args) {
        System.exit(new CommandLine(new ReachabilityAnalyzerCli()).execute(args));
    }

    @Override
    public void run() {
        System.out.println("reachability-analyzer " + VERSION
                + ": pipeline not wired yet (skeleton build). Use --help for usage.");
    }
}
