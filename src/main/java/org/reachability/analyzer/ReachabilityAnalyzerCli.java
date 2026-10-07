package org.reachability.analyzer;

import org.reachability.analyzer.analysis.AnalysisContext;
import org.reachability.analyzer.analysis.AnalysisException;
import org.reachability.analyzer.analysis.ArtifactClassIndex;
import org.reachability.analyzer.analysis.CallGraphFactory;
import org.reachability.analyzer.analysis.EntryPointDetector;
import org.reachability.analyzer.analysis.ReachabilityChecker;
import org.reachability.analyzer.analysis.SootUpSetup;
import org.reachability.analyzer.analysis.VulnMappingFormatException;
import org.reachability.analyzer.analysis.VulnMappingLoader;
import org.reachability.analyzer.osv.OsvRepository;
import org.reachability.analyzer.osv.SnapshotChecksum;
import org.reachability.analyzer.osv.VulnerabilityCandidate;
import org.reachability.analyzer.osv.VulnerabilityCandidates;
import org.reachability.analyzer.report.AnalysisReport;
import org.reachability.analyzer.report.JUnitXmlReportWriter;
import org.reachability.analyzer.report.JsonReportWriter;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;
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
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Callable;

/**
 * CLI entry point. Options and exit-code contract per the implementation plan
 * (T11, A8). The full pipeline (SBOM + OSV candidates, SootUp call graph,
 * verdicts) is wired from M4; the dry-run modes debug each stage in isolation.
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

    @Option(names = "--entry-points", split = ",",
            description = "Explicit entry points (class#method, comma-separated); "
                    + "wins over auto-detection.")
    List<String> entryPoints;

    @Option(names = "--callback-interfaces", split = ",",
            description = "Additional callback interfaces (class#method, comma-separated) "
                    + "for entry-point detection (extends the curated list, A13).")
    List<String> callbackInterfaces;

    @Option(names = "--dry-run-graph", hidden = true,
            description = "Build the call graph, print entry points + node/edge counts, and exit.")
    boolean dryRunGraph;

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
        if (dryRunGraph) {
            return dryRunGraph();
        }
        return analyze();
    }

    /**
     * M4 T44: the full pipeline — SBOM + OSV candidates, then bytecode
     * guard, view, entry points, call graph, and per-candidate verdicts.
     * M5 T51-T54: verdicts become the JSON + JUnit XML reports (per
     * --format) and the console summary table. Exit 1 when any candidate
     * is REACHABLE, 0 otherwise; 2 for usage errors; 3 for analysis
     * failures (including an unwritable report destination).
     */
    private int analyze() {
        long started = System.currentTimeMillis();
        if (sbom == null || osvDir == null || appClasses == null) {
            System.err.println("ERROR: analysis requires --sbom, --osv-dir and --app-classes");
            return CliResult.USAGE_ERROR.exitCode();
        }
        for (String format : formats) {
            if (!format.equals("json") && !format.equals("junitxml")) {
                System.err.println("ERROR: unknown report format: " + format + " (expected json, junitxml)");
                return CliResult.USAGE_ERROR.exitCode();
            }
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

        List<VulnerabilityCandidate> candidates = VulnerabilityCandidates.collect(parsed, repository);
        if (candidates.isEmpty()) {
            System.out.println("No vulnerability candidates: SBOM components do not match any OSV record.");
            return CliResult.OK.exitCode();
        }

        AnalysisContext context;
        try {
            context = AnalysisContext.of(appClasses, classpathFile);
        } catch (IOException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.USAGE_ERROR.exitCode();
        }
        for (String warning : context.warnings()) {
            System.err.println("WARNING: " + warning);
        }

        JavaView view;
        try {
            view = SootUpSetup.buildView(context, javaVersion);
        } catch (AnalysisException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }

        EntryPointDetector detector = new EntryPointDetector();
        List<MethodSignature> detected = detector.detect(view, context.appClassNames(),
                entryPoints == null ? List.<String>of() : entryPoints, parseCallbackInterfaces(callbackInterfaces));
        for (String warning : detector.warnings()) {
            System.err.println("WARNING: " + warning);
        }
        if (detected.isEmpty()) {
            System.err.println("ERROR: no entry points detected in " + appClasses
                    + " — pass --entry-points class#method explicitly");
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }
        if (verbose) {
            System.out.println("Detected entry points:");
            detected.forEach(entryPoint -> System.out.println("  " + entryPoint));
        }

        CallGraphFactory.BuildResult result;
        try {
            result = CallGraphFactory.build(view, detected, cha);
        } catch (AnalysisException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }
        if (verbose) {
            System.out.println("call graph (" + (cha ? "CHA" : "RTA") + "): "
                    + result.nodeCount() + " nodes, " + result.edgeCount() + " calls, "
                    + result.buildMillis() + " ms");
        }

        Map<String, List<VulnMappingLoader.VulnTarget>> mapping;
        if (mappings != null) {
            try {
                mapping = new VulnMappingLoader().load(mappings);
            } catch (VulnMappingFormatException e) {
                System.err.println("ERROR: " + e.getMessage());
                return CliResult.USAGE_ERROR.exitCode();
            } catch (IOException e) {
                System.err.println("ERROR: cannot read mappings file: " + e.getMessage());
                return CliResult.USAGE_ERROR.exitCode();
            }
        } else {
            mapping = Map.of();
        }

        ArtifactClassIndex index = new ArtifactClassIndex(context.jars());
        for (String warning : index.warnings()) {
            System.err.println("WARNING: " + warning);
        }

        ReachabilityChecker checker = new ReachabilityChecker(view, result.graph(), detected);
        List<ReachabilityChecker.Verdict> verdicts = checker.check(candidates, mapping, index);
        for (String warning : checker.warnings()) {
            System.err.println("WARNING: " + warning);
        }

        int reachableCount = 0;
        for (ReachabilityChecker.Verdict verdict : verdicts) {
            VulnerabilityCandidate candidate = verdict.candidate();
            if (verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE) {
                reachableCount++;
                System.out.println("CRITICAL: " + candidate.displayId() + " "
                        + candidate.componentName() + " " + candidate.componentVersion() + " REACHABLE");
                System.out.println("  path: " + String.join(" -> ", verdict.path()));
            } else if (verdict.status() == ReachabilityChecker.VerdictStatus.UNREACHABLE) {
                System.out.println("NOTICE: " + candidate.displayId() + " "
                        + candidate.componentName() + " " + candidate.componentVersion() + " UNREACHABLE"
                        + (verdict.onClasspath()
                                ? " (artifact present in classpath - possible reflection or dynamic dispatch risk)"
                                : ""));
            } else {
                System.out.println("NOTICE: " + candidate.displayId() + " "
                        + candidate.componentName() + " " + candidate.componentVersion()
                        + " UNREACHABLE (artifact not on classpath - no class info)");
            }
        }
        System.out.println(candidates.size() + " candidate(s): " + reachableCount + " reachable");
        printVerdictTable(verdicts);

        AnalysisReport report = buildReport(System.currentTimeMillis() - started, context, result,
                detected, repository, verdicts);
        List<String> written = new ArrayList<>();
        for (String format : formats) {
            Path file = reportFile(format);
            try {
                if (format.equals("json")) {
                    new JsonReportWriter().write(report, file);
                } else {
                    new JUnitXmlReportWriter().write(report, file);
                }
                written.add(file.toString());
            } catch (IOException e) {
                System.err.println("ERROR: cannot write report " + file + ": " + e.getMessage());
                return CliResult.ANALYSIS_FAILURE.exitCode();
            }
        }
        if (verbose) {
            System.out.println("reports written: " + String.join(", ", written));
            System.out.println("analysis took " + (System.currentTimeMillis() - started)
                    + " ms (call graph: " + result.buildMillis() + " ms)");
        }
        return reachableCount > 0 ? CliResult.REACHABLE_VULNERABILITIES.exitCode() : CliResult.OK.exitCode();
    }

    /** M5 T54: the console summary table — id, component, verdict, path head. */
    private void printVerdictTable(List<ReachabilityChecker.Verdict> verdicts) {
        String[] header = {"VULN ID", "COMPONENT", "VERDICT", "PATH"};
        List<String[]> rows = new ArrayList<>();
        for (ReachabilityChecker.Verdict verdict : verdicts) {
            VulnerabilityCandidate candidate = verdict.candidate();
            String pathHead = verdict.path().isEmpty() ? "-" : verdict.path().get(0);
            rows.add(new String[]{candidate.vulnId(), candidate.componentName(),
                    verdict.status().name(), pathHead});
        }
        int[] widths = columnWidths(header, rows);
        System.out.printf(format(widths), header);
        for (String[] row : rows) {
            System.out.printf(format(widths), row);
        }
    }

    /** M5 T51: assembles the report model from the run's measured state. */
    private AnalysisReport buildReport(long durationMillis, AnalysisContext context,
                                       CallGraphFactory.BuildResult result, List<MethodSignature> detected,
                                       OsvRepository repository, List<ReachabilityChecker.Verdict> verdicts) {
        String osvSha256 = null;
        try {
            osvSha256 = SnapshotChecksum.sha256OfDirectory(osvDir);
        } catch (IOException e) {
            System.err.println("WARNING: cannot hash OSV directory: " + e.getMessage());
        }
        AnalysisReport.ReportMetadata metadata = new AnalysisReport.ReportMetadata(
                "0.1.0-SNAPSHOT", cha ? "CHA" : "RTA", detected.size(),
                result.nodeCount(), result.edgeCount(), durationMillis,
                context.maxBytecodeMajor(), osvSha256,
                repository.fileCount() - repository.validRecordCount());
        List<AnalysisReport.VulnerabilityEntry> entries = new ArrayList<>();
        for (ReachabilityChecker.Verdict verdict : verdicts) {
            VulnerabilityCandidate candidate = verdict.candidate();
            entries.add(new AnalysisReport.VulnerabilityEntry(
                    candidate.vulnId(), candidate.purl(), candidate.componentName(),
                    candidate.componentVersion(),
                    verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE ? "REACHABLE" : "UNREACHABLE",
                    verdict.onClasspath(), candidate.severities(),
                    String.join("; ", candidate.matchedBy()), verdict.path()));
        }
        return new AnalysisReport(metadata, entries);
    }

    /** {@code <output>.json} or {@code <output>.junit.xml} per the format token. */
    private Path reportFile(String format) {
        Path fileName = output.getFileName();
        String base = fileName == null ? output.toString() : fileName.toString();
        String suffix = format.equals("json") ? ".json" : ".junit.xml";
        Path parent = output.getParent();
        return parent == null ? Path.of(base + suffix) : parent.resolve(base + suffix);
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

    /**
     * M3 T31-T34 debug mode: app classes + classpath file → bytecode guard →
     * view → entry points → call graph (RTA or CHA) → node/edge counts.
     */
    private int dryRunGraph() {
        if (appClasses == null) {
            System.err.println("ERROR: --dry-run-graph requires --app-classes <dir>");
            return CliResult.USAGE_ERROR.exitCode();
        }
        AnalysisContext context;
        try {
            context = AnalysisContext.of(appClasses, classpathFile);
        } catch (IOException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.USAGE_ERROR.exitCode();
        }
        for (String warning : context.warnings()) {
            System.err.println("WARNING: " + warning);
        }

        JavaView view;
        try {
            view = SootUpSetup.buildView(context, javaVersion);
        } catch (AnalysisException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }

        EntryPointDetector detector = new EntryPointDetector();
        List<MethodSignature> detected = detector.detect(view, context.appClassNames(),
                entryPoints == null ? List.<String>of() : entryPoints, parseCallbackInterfaces(callbackInterfaces));
        for (String warning : detector.warnings()) {
            System.err.println("WARNING: " + warning);
        }
        if (detected.isEmpty()) {
            System.err.println("ERROR: no entry points detected in " + appClasses
                    + " — pass --entry-points class#method explicitly");
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }
        if (verbose) {
            System.out.println("Detected entry points:");
            detected.forEach(entryPoint -> System.out.println("  " + entryPoint));
        }

        CallGraphFactory.BuildResult result;
        try {
            result = CallGraphFactory.build(view, detected, cha);
        } catch (AnalysisException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }
        System.out.println("call graph (" + (cha ? "CHA" : "RTA") + "): "
                + result.nodeCount() + " nodes, " + result.edgeCount() + " calls, "
                + result.buildMillis() + " ms");
        return CliResult.OK.exitCode();
    }

    /** {@code class#method} list into an interface → callback methods map (A13). */
    private static Map<String, List<String>> parseCallbackInterfaces(List<String> raw) {
        Map<String, List<String>> result = new TreeMap<>();
        if (raw == null) {
            return result;
        }
        for (String entry : raw) {
            int hash = entry.indexOf('#');
            if (hash <= 0 || hash == entry.length() - 1) {
                continue;
            }
            result.computeIfAbsent(entry.substring(0, hash), key -> new ArrayList<>())
                    .add(entry.substring(hash + 1));
        }
        return result;
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
