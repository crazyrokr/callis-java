package org.reachability.analyzer;

import org.reachability.analyzer.sbom.ParsedSbom;
import org.reachability.analyzer.sbom.SbomComponent;
import org.reachability.analyzer.sbom.SbomFormatException;
import org.reachability.analyzer.sbom.SbomReader;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * CLI entry point. Options and exit-code contract per the implementation plan
 * (T11, A8); the analysis pipeline itself lands in M2-M6.
 */
@Command(
        name = "reachability-analyzer",
        version = "reachability-analyzer 0.1.0-SNAPSHOT",
        mixinStandardHelpOptions = true,
        description = "Determines whether vulnerabilities listed in a CycloneDX SBOM are "
                + "reachable from application code, using a SootUp call graph."
)
public final class ReachabilityAnalyzerCli implements Callable<Integer> {

    @Option(names = "--app-classes",
            description = "Directory with the compiled application classes to analyze.")
    Path appClasses;

    @Option(names = "--classpath-file",
            description = "File with the resolved dependency classpath "
                    + "(colon- or newline-separated jar list).")
    Path classpathFile;

    @Option(names = "--sbom", description = "Path to the CycloneDX bom.json of the target project.")
    Path sbom;

    @Option(names = "--osv-dir", description = "Directory with local OSV Maven records.")
    Path osvDir;

    @Option(names = "--mappings",
            description = "Optional vuln-mappings.json (vuln id to class/method entries).")
    Path mappings;

    @Option(names = "--cha", description = "Build the call graph with CHA instead of RTA.")
    boolean cha;

    @Option(names = "--java-version",
            description = "Expected Java version of the target (informational hint for the guard).")
    Integer javaVersion;

    @Option(names = "--output", defaultValue = "reachability-report",
            description = "Base name for the generated reports.")
    Path output;

    @Option(names = "--format", split = ",", defaultValue = "json,junitxml",
            description = "Report formats to write (json, junitxml).")
    List<String> formats;

    @Option(names = {"-v", "--verbose"}, description = "Verbose diagnostics.")
    boolean verbose;

    @Option(names = "--dry-run-sbom", hidden = true,
            description = "Parse the SBOM, print the component table, and exit.")
    boolean dryRunSbom;

    public static void main(String[] args) {
        System.exit(new CommandLine(new ReachabilityAnalyzerCli()).execute(args));
    }

    @Override
    public Integer call() {
        if (dryRunSbom) {
            return dryRunSbom();
        }
        System.out.println("reachability-analyzer: analysis pipeline not wired yet "
                + "(M1 skeleton build). Use --dry-run-sbom or wait for M2-M6.");
        return CliResult.USAGE_ERROR.exitCode();
    }

    private int dryRunSbom() {
        if (sbom == null) {
            System.err.println("ERROR: --dry-run-sbom requires --sbom <file>");
            return CliResult.USAGE_ERROR.exitCode();
        }
        ParsedSbom parsed;
        try {
            parsed = SbomReader.parse(sbom);
        } catch (SbomFormatException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.USAGE_ERROR.exitCode();
        } catch (IOException e) {
            System.err.println("ERROR: cannot read SBOM file: " + e.getMessage());
            return CliResult.USAGE_ERROR.exitCode();
        }

        for (String warning : parsed.getWarnings()) {
            System.err.println("WARNING: " + warning);
        }
        printComponentTable(parsed.getComponents());
        return CliResult.OK.exitCode();
    }

    private void printComponentTable(List<SbomComponent> components) {
        if (components.isEmpty()) {
            System.out.println("No maven components found in the SBOM.");
            return;
        }
        String[] header = {"NAME", "VERSION", "PURL"};
        List<String[]> rows = new ArrayList<>();
        for (SbomComponent component : components) {
            String version = component.getVersion() == null ? "?" : component.getVersion();
            rows.add(new String[]{component.getName(), version, component.getPurl().toString()});
        }
        int nameWidth = Math.max(header[0].length(),
                components.stream().mapToInt(c -> c.getName().length()).max().orElse(0));
        int versionWidth = Math.max(header[1].length(),
                rows.stream().mapToInt(r -> r[1].length()).max().orElse(0));
        System.out.printf("%-" + nameWidth + "s  %-" + versionWidth + "s  %s%n",
                header[0], header[1], header[2]);
        for (String[] row : rows) {
            System.out.printf("%-" + nameWidth + "s  %-" + versionWidth + "s  %s%n",
                    row[0], row[1], row[2]);
        }
        System.out.println(components.size() + " maven component(s)");
    }
}
