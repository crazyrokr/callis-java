package org.reachability.analyzer.engine;

import org.reachability.analyzer.CliResult;
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
import org.reachability.analyzer.report.SarifReportWriter;
import org.reachability.analyzer.sbom.ParsedSbom;
import org.reachability.analyzer.sbom.SbomFormatException;
import org.reachability.analyzer.sbom.SbomReader;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * M7a (A10): the engine facade — the single in-process pipeline the CLI and
 * the Gradle/Maven plugins share. M4 T44 pipeline (SBOM + OSV candidates,
 * bytecode guard, view, entry points, call graph, verdicts) plus the M5
 * report generation: exit 1 when any candidate is REACHABLE, 0 otherwise;
 * 2 for usage errors; 3 for analysis failures (including an unwritable
 * report destination). All console output flows through the
 * {@link DiagnosticSink} — the CLI plugs in the real console, plugins in a
 * collector — so the same diagnostics reach both front ends.
 *
 * <p>Contract notes: a run that ends before report generation deletes any
 * previous run's report files under {@code output} (they would be mistaken
 * for this run's result); {@code --osv-checksum} mismatches fail with exit 2
 * (A14); an OSV directory with record files but zero valid records fails with
 * exit 3 (fail-safe, A14).
 */
public final class AnalyzerEngine {

    private AnalyzerEngine() {
    }

    public static AnalysisResult analyze(AnalysisRequest request, Path output,
                                         List<ReportFormat> formats, boolean verbose, DiagnosticSink sink) {
        long started = System.currentTimeMillis();
        List<Path> reportFiles = new ArrayList<>();
        for (ReportFormat format : formats) {
            Path reportFile = reportFile(output, format);
            reportFiles.add(reportFile);
            // A run that ends before report generation (zero candidates,
            // analysis failure) must not leave a previous run's reports
            // behind — they would be mistaken for this run's result.
            try {
                Files.deleteIfExists(reportFile);
            } catch (IOException e) {
                sink.err("WARNING: cannot delete previous report "
                        + reportFile + ": " + e.getMessage());
            }
        }

        ParsedSbom parsed = loadSbom(request.sbom(), sink);
        if (parsed == null) {
            return new AnalysisResult(CliResult.USAGE_ERROR.exitCode(), Optional.empty());
        }

        OsvRepository repository;
        try {
            repository = new OsvRepository(request.osvDir());
        } catch (IOException e) {
            sink.err("ERROR: cannot read OSV directory: " + e.getMessage());
            return new AnalysisResult(CliResult.USAGE_ERROR.exitCode(), Optional.empty());
        }
        for (String warning : repository.warnings()) {
            sink.err("WARNING: " + warning);
        }
        if (request.expectedOsvChecksum().isPresent()
                && !verifyOsvChecksum(request.osvDir(), request.expectedOsvChecksum().get(), sink)) {
            return new AnalysisResult(CliResult.USAGE_ERROR.exitCode(), Optional.empty());
        }
        if (repository.fileCount() > 0 && repository.validRecordCount() == 0) {
            sink.err("ERROR: OSV directory contains " + repository.fileCount()
                    + " record file(s) but zero valid records; refusing to pass silently");
            return new AnalysisResult(CliResult.ANALYSIS_FAILURE.exitCode(), Optional.empty());
        }
        for (String warning : parsed.getWarnings()) {
            sink.err("WARNING: " + warning);
        }

        List<VulnerabilityCandidate> candidates = VulnerabilityCandidates.collect(parsed, repository);
        if (candidates.isEmpty()) {
            sink.out("No vulnerability candidates: SBOM components do not match any OSV record.");
            return new AnalysisResult(CliResult.OK.exitCode(), Optional.empty());
        }

        AnalysisContext context;
        try {
            context = AnalysisContext.of(request.appClasses(), request.classpathFile());
        } catch (IOException e) {
            sink.err("ERROR: " + e.getMessage());
            return new AnalysisResult(CliResult.USAGE_ERROR.exitCode(), Optional.empty());
        }
        for (String warning : context.warnings()) {
            sink.err("WARNING: " + warning);
        }

        JavaView view;
        try {
            view = SootUpSetup.buildView(context, request.expectedJavaVersion().orElse(null));
        } catch (AnalysisException e) {
            sink.err("ERROR: " + e.getMessage());
            return new AnalysisResult(CliResult.ANALYSIS_FAILURE.exitCode(), Optional.empty());
        }

        EntryPointDetector detector = new EntryPointDetector();
        List<MethodSignature> detected = detector.detect(view, context.appClassNames(),
                request.entryPoints(), request.callbackInterfaces());
        for (String warning : detector.warnings()) {
            sink.err("WARNING: " + warning);
        }
        if (detected.isEmpty()) {
            sink.err("ERROR: no entry points detected in " + request.appClasses()
                    + " — pass --entry-points class#method explicitly");
            return new AnalysisResult(CliResult.ANALYSIS_FAILURE.exitCode(), Optional.empty());
        }
        if (verbose) {
            sink.out("Detected entry points:");
            detected.forEach(entryPoint -> sink.out("  " + entryPoint));
        }

        CallGraphFactory.BuildResult result;
        try {
            result = CallGraphFactory.build(view, detected, request.policy());
        } catch (AnalysisException e) {
            sink.err("ERROR: " + e.getMessage());
            return new AnalysisResult(CliResult.ANALYSIS_FAILURE.exitCode(), Optional.empty());
        }
        if (verbose) {
            sink.out("call graph (" + request.policy() + "): "
                    + result.nodeCount() + " nodes, " + result.edgeCount() + " calls, "
                    + result.buildMillis() + " ms");
        }

        Map<String, List<VulnMappingLoader.VulnTarget>> mapping;
        if (request.mappings().isPresent()) {
            try {
                mapping = new VulnMappingLoader().load(request.mappings().get());
            } catch (VulnMappingFormatException e) {
                sink.err("ERROR: " + e.getMessage());
                return new AnalysisResult(CliResult.USAGE_ERROR.exitCode(), Optional.empty());
            } catch (IOException e) {
                sink.err("ERROR: cannot read mappings file: " + e.getMessage());
                return new AnalysisResult(CliResult.USAGE_ERROR.exitCode(), Optional.empty());
            }
        } else {
            mapping = Map.of();
        }

        ArtifactClassIndex index = new ArtifactClassIndex(context.jars());
        for (String warning : index.warnings()) {
            sink.err("WARNING: " + warning);
        }

        ReachabilityChecker checker = new ReachabilityChecker(view, result.graph(), detected);
        List<ReachabilityChecker.Verdict> verdicts = checker.check(candidates, mapping, index);
        for (String warning : checker.warnings()) {
            sink.err("WARNING: " + warning);
        }

        int reachableCount = 0;
        for (ReachabilityChecker.Verdict verdict : verdicts) {
            VulnerabilityCandidate candidate = verdict.candidate();
            if (verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE) {
                reachableCount++;
                sink.out("CRITICAL: " + candidate.displayId() + " "
                        + candidate.componentName() + " " + candidate.componentVersion() + " REACHABLE");
                sink.out("  path: " + String.join(" -> ", verdict.path()));
            } else if (verdict.status() == ReachabilityChecker.VerdictStatus.UNREACHABLE) {
                sink.out("NOTICE: " + candidate.displayId() + " "
                        + candidate.componentName() + " " + candidate.componentVersion() + " UNREACHABLE"
                        + (verdict.onClasspath()
                                ? " (artifact present in classpath - possible reflection or dynamic dispatch risk)"
                                : ""));
            } else {
                sink.out("NOTICE: " + candidate.displayId() + " "
                        + candidate.componentName() + " " + candidate.componentVersion()
                        + " UNREACHABLE (artifact not on classpath - no class info)");
            }
        }
        sink.out(candidates.size() + " candidate(s): " + reachableCount + " reachable");
        printVerdictTable(sink, verdicts);

        AnalysisReport report = buildReport(System.currentTimeMillis() - started, context, result,
                request.policy(), detected, request.osvDir(), request.sbom(), repository, verdicts, sink);
        List<String> written = new ArrayList<>();
        for (int i = 0; i < formats.size(); i++) {
            Path file = reportFiles.get(i);
            try {
                if (formats.get(i) == ReportFormat.JSON) {
                    new JsonReportWriter().write(report, file);
                } else if (formats.get(i) == ReportFormat.JUNITXML) {
                    new JUnitXmlReportWriter().write(report, file);
                } else {
                    new SarifReportWriter().write(report, file);
                }
                written.add(file.toString());
            } catch (IOException e) {
                sink.err("ERROR: cannot write report " + file + ": " + e.getMessage());
                return new AnalysisResult(CliResult.ANALYSIS_FAILURE.exitCode(), Optional.empty());
            }
        }
        if (verbose) {
            sink.out("reports written: " + String.join(", ", written));
            sink.out("analysis took " + (System.currentTimeMillis() - started)
                    + " ms (call graph: " + result.buildMillis() + " ms)");
        }
        return new AnalysisResult(
                reachableCount > 0 ? CliResult.REACHABLE_VULNERABILITIES.exitCode() : CliResult.OK.exitCode(),
                Optional.of(report));
    }

    /** M5 T54: the console summary table — id, component, verdict, path head. */
    private static void printVerdictTable(DiagnosticSink sink, List<ReachabilityChecker.Verdict> verdicts) {
        String[] header = {"VULN ID", "COMPONENT", "VERDICT", "PATH"};
        List<String[]> rows = new ArrayList<>();
        for (ReachabilityChecker.Verdict verdict : verdicts) {
            VulnerabilityCandidate candidate = verdict.candidate();
            String pathHead = verdict.path().isEmpty() ? "-" : verdict.path().get(0);
            rows.add(new String[]{candidate.vulnId(), candidate.componentName(),
                    verdict.status().name(), pathHead});
        }
        TablePrinter.print(sink, header, rows);
    }

    /** M5 T51: assembles the report model from the run's measured state. */
    private static AnalysisReport buildReport(long durationMillis, AnalysisContext context,
                                             CallGraphFactory.BuildResult result, CallGraphPolicy policy,
                                             List<MethodSignature> detected, Path osvDir, Path sbom,
                                             OsvRepository repository,
                                             List<ReachabilityChecker.Verdict> verdicts, DiagnosticSink sink) {
        String osvSha256 = null;
        try {
            osvSha256 = SnapshotChecksum.sha256OfDirectory(osvDir);
        } catch (IOException e) {
            sink.err("WARNING: cannot hash OSV directory: " + e.getMessage());
        }
        AnalysisReport.ReportMetadata metadata = new AnalysisReport.ReportMetadata(
                "0.1.0-SNAPSHOT", policy.name(), detected.size(),
                result.nodeCount(), result.edgeCount(), durationMillis,
                context.maxBytecodeMajor(), osvSha256,
                repository.fileCount() - repository.validRecordCount(),
                sbom == null ? null : sbom.toString());
        List<AnalysisReport.VulnerabilityEntry> entries = new ArrayList<>();
        for (ReachabilityChecker.Verdict verdict : verdicts) {
            VulnerabilityCandidate candidate = verdict.candidate();
            entries.add(new AnalysisReport.VulnerabilityEntry(
                    candidate.vulnId(), candidate.purl(), candidate.componentName(),
                    candidate.componentVersion(),
                    verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE ? "REACHABLE" : "UNREACHABLE",
                    verdict.onClasspath(), candidate.summary(), candidate.severities(),
                    String.join("; ", candidate.matchedBy()), verdict.path()));
        }
        return new AnalysisReport(metadata, entries);
    }

    /** {@code <output><suffix>} per the format; parent of a bare name is the cwd. */
    private static Path reportFile(Path output, ReportFormat format) {
        Path fileName = output.getFileName();
        String base = fileName == null ? output.toString() : fileName.toString();
        Path parent = output.getParent();
        return parent == null
                ? Path.of(base + format.suffix())
                : parent.resolve(base + format.suffix());
    }

    /** A14: the pin refuses a changed snapshot; hash failure is a usage error. */
    private static boolean verifyOsvChecksum(Path osvDir, String expected, DiagnosticSink sink) {
        String actual;
        try {
            actual = SnapshotChecksum.sha256OfDirectory(osvDir);
        } catch (IOException e) {
            sink.err("ERROR: cannot hash OSV directory: " + e.getMessage());
            return false;
        }
        if (!actual.equals(expected)) {
            sink.err("ERROR: OSV snapshot checksum mismatch: expected "
                    + expected + ", found " + actual);
            return false;
        }
        return true;
    }

    private static ParsedSbom loadSbom(Path sbom, DiagnosticSink sink) {
        try {
            return SbomReader.parse(sbom);
        } catch (SbomFormatException e) {
            sink.err("ERROR: " + e.getMessage());
            return null;
        } catch (IOException e) {
            sink.err("ERROR: cannot read SBOM file: " + e.getMessage());
            return null;
        }
    }
}
