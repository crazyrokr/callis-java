package org.reachability.analyzer;

import org.reachability.analyzer.analysis.AnalysisContext;
import org.reachability.analyzer.analysis.AnalysisException;
import org.reachability.analyzer.analysis.CallGraphFactory;
import org.reachability.analyzer.analysis.EntryPointDetector;
import org.reachability.analyzer.analysis.SootUpSetup;
import org.reachability.analyzer.engine.AnalysisRequest;
import org.reachability.analyzer.engine.AnalyzerEngine;
import org.reachability.analyzer.engine.CallGraphPolicy;
import org.reachability.analyzer.engine.CallbackInterfaceSpecs;
import org.reachability.analyzer.engine.DiagnosticSink;
import org.reachability.analyzer.engine.ReportFormat;
import org.reachability.analyzer.engine.TablePrinter;
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
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.Callable;

/**
 * CLI entry point. Options and exit-code contract per the implementation plan
 * (T11, A8). M7a (A10): the full pipeline lives in the core engine facade
 * ({@link AnalyzerEngine}) — this class maps options onto an
 * {@link AnalysisRequest}, hands it over together with the console as a
 * {@link DiagnosticSink}, and returns the engine's exit code; the dry-run
 * modes debug each stage in isolation.
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

    @Option(names = "--pointer-analysis",
            description = "Build the call graph with SPARK object-sensitive pointer analysis "
                    + "instead of RTA (M7b; slower, prunes dispatch to receivers that are "
                    + "instantiated but never used at the call site).")
    boolean pointerAnalysis;

    @Option(names = "--java-version",
            description = "Expected Java version of the target (informational hint for the guard).")
    Integer javaVersion;

    @Option(names = "--output", defaultValue = "reachability-report",
            description = "Base name for the generated reports.")
    Path output;

    @Option(names = "--format", split = ",", defaultValue = "json,junitxml",
            description = "Report formats to write (json, junitxml, sarif).")
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
        if (cha && pointerAnalysis) {
            System.err.println("ERROR: --pointer-analysis and --cha are mutually exclusive");
            return CliResult.USAGE_ERROR.exitCode();
        }
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
     * M7a (A10): argument validation, then the full pipeline via the core
     * engine facade — the same code path the Gradle/Maven plugins call
     * in-process. Exit-code contract (A8) is returned from the engine:
     * 0 = no reachable vulnerability, 1 = at least one REACHABLE,
     * 2 = usage error, 3 = analysis failure (including an unwritable
     * report destination).
     */
    private int analyze() {
        if (sbom == null || osvDir == null || appClasses == null) {
            System.err.println("ERROR: analysis requires --sbom, --osv-dir and --app-classes");
            return CliResult.USAGE_ERROR.exitCode();
        }
        List<ReportFormat> reportFormats = new ArrayList<>();
        for (String token : formats) {
            ReportFormat format = parseFormat(token);
            if (format == null) {
                System.err.println("ERROR: unknown report format: " + token + " (expected json, junitxml, sarif)");
                return CliResult.USAGE_ERROR.exitCode();
            }
            reportFormats.add(format);
        }
        DiagnosticSink sink = DiagnosticSink.of(System.out, System.err);
        return AnalyzerEngine.analyze(request(), output, reportFormats, verbose, sink).exitCode();
    }

    /** {@code json}/{@code junitxml}/{@code sarif} tokens onto {@link ReportFormat}; anything else is a usage error. */
    private static ReportFormat parseFormat(String token) {
        if (token.equals("json")) {
            return ReportFormat.JSON;
        }
        if (token.equals("junitxml")) {
            return ReportFormat.JUNITXML;
        }
        if (token.equals("sarif")) {
            return ReportFormat.SARIF;
        }
        return null;
    }

    private AnalysisRequest request() {
        return new AnalysisRequest(
                appClasses,
                classpathFile,
                sbom,
                osvDir,
                Optional.ofNullable(osvChecksum),
                Optional.ofNullable(mappings),
                policy(),
                entryPoints == null ? List.of() : entryPoints,
                CallbackInterfaceSpecs.parse(callbackInterfaces),
                Optional.ofNullable(javaVersion));
    }

    /** The graph policy from the two exclusive flags (validated in {@link #call()}); RTA is the default. */
    private CallGraphPolicy policy() {
        if (cha) {
            return CallGraphPolicy.CHA;
        }
        if (pointerAnalysis) {
            return CallGraphPolicy.SPARK;
        }
        return CallGraphPolicy.RTA;
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
                entryPoints == null ? List.<String>of() : entryPoints,
                CallbackInterfaceSpecs.parse(callbackInterfaces));
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

        CallGraphPolicy policy = policy();
        CallGraphFactory.BuildResult result;
        try {
            result = CallGraphFactory.build(view, detected, policy);
        } catch (AnalysisException e) {
            System.err.println("ERROR: " + e.getMessage());
            return CliResult.ANALYSIS_FAILURE.exitCode();
        }
        System.out.println("call graph (" + policy + "): "
                + result.nodeCount() + " nodes, " + result.edgeCount() + " calls, "
                + result.buildMillis() + " ms");
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
        TablePrinter.print(DiagnosticSink.of(System.out, System.err), header, rows);
        System.out.println(candidates.size() + " candidate(s)");
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
