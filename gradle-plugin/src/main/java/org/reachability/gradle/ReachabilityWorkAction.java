package org.reachability.gradle;

import javax.inject.Inject;

import org.gradle.api.GradleException;
import org.gradle.api.logging.Logging;
import org.gradle.api.logging.Logger;
import org.gradle.internal.instantiation.InstanceGenerator;
import org.gradle.workers.WorkAction;
import org.gradle.workers.WorkParameters;
import org.gradle.workers.internal.DefaultWorkResult;
import org.gradle.workers.internal.ProvidesWorkResult;
import org.reachability.analyzer.engine.AnalysisRequest;
import org.reachability.analyzer.engine.AnalyzerEngine;
import org.reachability.analyzer.engine.CallGraphPolicy;
import org.reachability.analyzer.engine.CallbackInterfaceSpecs;
import org.reachability.analyzer.engine.DiagnosticSink;
import org.reachability.analyzer.engine.ReportFormat;

import java.lang.management.ManagementFactory;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A10 (M9): the reachability analysis as a forked work action. The task
 * configures the parameters (strings and lists - nothing live crosses the
 * process boundary); the worker deserializes them and calls the @Inject
 * constructor. Gradle 9.8 delivers configured parameters to a work action
 * only when it implements the internal {@link ProvidesWorkResult} marker
 * (on the gradleApi() classpath in this build) with an @Inject
 * (WorkParameters, InstanceGenerator) constructor - a plain action runs but
 * silently receives nothing (probed), so the contract is pinned by
 * ReachabilityPluginSpec. The worker announces its own pid so a run is
 * attributable to the forked process; a non-zero engine exit rethrows and
 * the task unwraps the failure to its own message.
 */
public class ReachabilityWorkAction implements WorkAction<ReachabilityWorkAction.Params>, ProvidesWorkResult {

    /** Every request field as a string or list; empty marks an absent optional. */
    public interface Params extends WorkParameters {
        String getAppClasses();

        void setAppClasses(String appClasses);

        String getClasspathFile();

        void setClasspathFile(String classpathFile);

        String getBomFile();

        void setBomFile(String bomFile);

        String getOsvDir();

        void setOsvDir(String osvDir);

        String getExpectedOsvChecksum();

        void setExpectedOsvChecksum(String expectedOsvChecksum);

        String getMappings();

        void setMappings(String mappings);

        String getPolicyName();

        void setPolicyName(String policyName);

        String getFormats();

        void setFormats(String formats);

        String getReportBase();

        void setReportBase(String reportBase);

        List<String> getEntryPoints();

        void setEntryPoints(List<String> entryPoints);

        List<String> getCallbackInterfaces();

        void setCallbackInterfaces(List<String> callbackInterfaces);
    }

    private final Params params;

    @Inject
    public ReachabilityWorkAction(Params params, InstanceGenerator generator) {
        this.params = params;
    }

    @Override
    public void execute() {
        if (params == null) {
            throw new GradleException("checkReachability: the worker received no parameters");
        }
        Logger logger = Logging.getLogger(ReachabilityWorkAction.class);
        logger.lifecycle("reachability: analysis runs in process " + ManagementFactory.getRuntimeMXBean().getPid());
        DiagnosticSink sink = new DiagnosticSink() {
            @Override
            public void out(String line) {
                logger.lifecycle(line);
            }

            @Override
            public void err(String line) {
                logger.error(line);
            }
        };
        int exitCode = AnalyzerEngine.analyze(request(), Path.of(params.getReportBase()),
                parseFormats(), false, sink).exitCode();
        if (exitCode == 1) {
            throw new GradleException("reachable vulnerabilities found - see " + reportFiles());
        }
        if (exitCode != 0) {
            throw new GradleException("reachability analysis failed (exit " + exitCode
                    + "); see the console output above");
        }
    }

    private AnalysisRequest request() {
        CallGraphPolicy policy = "SPARK".equals(params.getPolicyName()) ? CallGraphPolicy.SPARK
                : "CHA".equals(params.getPolicyName()) ? CallGraphPolicy.CHA : CallGraphPolicy.RTA;
        Optional<String> checksum = empty(params.getExpectedOsvChecksum())
                ? Optional.empty() : Optional.of(params.getExpectedOsvChecksum());
        Optional<Path> mappings = empty(params.getMappings())
                ? Optional.empty() : Optional.of(Path.of(params.getMappings()));
        return new AnalysisRequest(
                Path.of(params.getAppClasses()),
                empty(params.getClasspathFile()) ? null : Path.of(params.getClasspathFile()),
                Path.of(params.getBomFile()),
                Path.of(params.getOsvDir()),
                checksum,
                mappings,
                policy,
                params.getEntryPoints(),
                CallbackInterfaceSpecs.parse(params.getCallbackInterfaces()),
                Optional.empty());
    }

    private static boolean empty(String value) {
        return value == null || value.isBlank();
    }

    private List<ReportFormat> parseFormats() {
        List<ReportFormat> formats = new ArrayList<>();
        for (String token : params.getFormats().split(",")) {
            ReportFormat format = token.equals("json") ? ReportFormat.JSON
                    : token.equals("junitxml") ? ReportFormat.JUNITXML
                    : token.equals("sarif") ? ReportFormat.SARIF
                    : null;
            if (format == null) {
                throw new GradleException("checkReachability: unknown report format '" + token
                        + "' (expected json, junitxml, sarif)");
            }
            formats.add(format);
        }
        return formats;
    }

    private String reportFiles() {
        List<String> files = new ArrayList<>();
        for (ReportFormat format : parseFormats()) {
            files.add(params.getReportBase() + format.suffix());
        }
        return String.join(", ", files);
    }

    @Override
    public Params getParameters() {
        return params;
    }

    @Override
    public DefaultWorkResult getWorkResult() {
        return DefaultWorkResult.SUCCESS;
    }
}
