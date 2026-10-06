package org.reachability.analyzer;

import org.reachability.analyzer.osv.OsvRepository;
import org.reachability.analyzer.osv.SnapshotChecksum;
import org.reachability.analyzer.osv.VulnerabilityCandidate;
import org.reachability.analyzer.osv.VulnerabilityCandidates;
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

    @Option(names = "--dry-run-match", hidden = true,
            description = "Match the SBOM against --osv-dir, print vulnerability candidates, and exit.")
    boolean dryRunMatch;

    @Option(names = "--osv-checksum",
            description = "Expected sha256 of the OSV snapshot directory (A14 pinning); "
                    + "a mismatch fails with exit 2.")
    String osvChecksum;

    public static void main(String[] args) {
        System.exit(new CommandLine(new ReachabilityAnalyzerCli()).execute(args));
    }

    @Override
    public Integer call() {
        if (dryRunSbom) {
            return dryRunSbom();
        }
        if (dryRunMatch) {
            return dryRunMatch();
        }
        System.out.println("reachability-analyzer: analysis pipeline not wired yet "
                + "(M1 skeleton build). Use --dry-run-sbom or wait for M3-M6.");
        return CliResult.USAGE_ERROR.exitCode();
    }

    private int dryRunSbom() {
        if (sbom == null) {
            System.err.println("ERROR: --dry-run-sbom requires --sbom <file>");
            return CliResult.USAGE_ERROR.exitCode();
        }
        ParsedSbom parsed = loadSbom();
        if (parsed == null) {
            return CliResult.USAGE_ERROR.exitCode();
        }
        for (String warning : parsed.getWarnings()) {
            System.err.println("WARNING: " + warning);
        }
        printComponentTable(parsed.getComponents());
        return CliResult.OK.exitCode();
    }

    /**
     * M2 T24: SBOM + OSV snapshot, print the vulnerability candidates,
     * exit 0. The SootUp pipeline (M3+) continues where this stops.
     */
    private int dryRunMatch() {
        if (sbom == null) {
            System.err.println("ERROR: --dry-run-match requires --sbom <file>");
            return CliResult.USAGE_ERROR.exitCode();
        }
        if (osvDir == null) {
            System.err.println("ERROR: --dry-run-match requires --osv-dir <dir>");
            return CliResult.USAGE_ERROR.exitCode();
        }
        ParsedSbom parsed = loadSbom();
        if (parsed == null) {
            return CliResult.USAGE_ERROR.exitCode();
        }

        OsvRepository repository;
        try {
            repository = new OsvRepository(osvDir);
        } catch (IOException e) {
            System.err.println("ERROR: cannot read OSV directory: " + e.getMessage());
            return CliResult.USAGE_ERROR.exitCode();
        }
        for (String warning : repository.warnings()) {
            System.err.println("WARNING: " + warning);
        }

        if (osvChecksum != null) {
            String actual;
            try {
                actual = SnapshotChecksum.sha256OfDirectory(osvDir);
            } catch (IOException e) {
                System.err.println("ERROR: cannot hash OSV directory: " + e.getMessage());
                return CliResult.USAGE_ERROR.exitCode();
            }
            if (!actual.equals(osvChecksum)) {
                System.err.println("ERROR: OSV snapshot checksum mismatch: expected "
                        + osvChecksum + ", found " + actual);
                return CliResult.USAGE_ERROR.exitCode();
            }
        }

        if (repository.fileCount() > 0 && repository.validRecordCount() == 0) {
            System.err.println("ERROR: OSV directory contains " + repository.fileCount()
                    + " record file(s) but zero valid records; refusing to pass silently");
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }

        for (String warning : parsed.getWarnings()) {
            System.err.println("WARNING: " + warning);
        }
        printCandidateTable(VulnerabilityCandidates.collect(parsed, repository));
        return CliResult.OK.exitCode();
    }

    private ParsedSbom loadSbom() {
        try {
            return SbomReader.parse(sbom);
        } catch (SbomFormatException e) {
            System.err.println("ERROR: " + e.getMessage());
            return null;
        } catch (IOException e) {
            System.err.println("ERROR: cannot read SBOM file: " + e.getMessage());
            return null;
        }
    }

    private void printCandidateTable(List<VulnerabilityCandidate> candidates) {
        if (candidates.isEmpty()) {
            System.out.println("No vulnerability candidates: SBOM components do not match any OSV record.");
            return;
        }
        String[] header = {"VULN ID", "ALIASES", "COMPONENT", "VERSION", "MATCHED NAME", "MATCHED BY"};
        List<String[]> rows = new ArrayList<>();
        for (VulnerabilityCandidate c : candidates) {
            rows.add(new String[]{
                    c.vulnId(),
                    String.join(", ", c.aliases()),
                    c.componentName(),
                    c.componentVersion(),
                    c.matchedName(),
                    String.join("; ", c.matchedBy())});
        }
        int[] widths = columnWidths(header, rows);
        System.out.printf(format(widths), header);
        for (String[] row : rows) {
            System.out.printf(format(widths), row);
        }
        System.out.println(candidates.size() + " candidate(s)");
    }

    private int[] columnWidths(String[] header, List<String[]> rows) {
        int[] widths = new int[header.length];
        for (int i = 0; i < header.length; i++) {
            widths[i] = header[i].length();
        }
        for (String[] row : rows) {
            for (int i = 0; i < widths.length; i++) {
                widths[i] = Math.max(widths[i], row[i].length());
            }
        }
        return widths;
    }

    private String format(int[] widths) {
        StringBuilder format = new StringBuilder();
        for (int width : widths) {
            format.append("%-").append(width).append("s  ");
        }
        format.append("%n");
        return format.toString();
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
