package org.reachability.gradle;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputFiles;
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.TaskAction;
import org.reachability.analyzer.engine.AnalysisRequest;
import org.reachability.analyzer.engine.AnalyzerEngine;
import org.reachability.analyzer.engine.CallGraphPolicy;
import org.reachability.analyzer.engine.CallbackInterfaceSpecs;
import org.reachability.analyzer.engine.DiagnosticSink;
import org.reachability.analyzer.engine.ReportFormat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A10 (M7e): runs the reachability analysis on the project's main source
 * set — compiled classes + resolved runtime classpath — and fails the
 * build when any SBOM vulnerability is reachable (engine exit 1), or when
 * the run itself was unusable (exit 2/3). Reports go to
 * {@code build/reachability-report.*}; a run that ends before report
 * generation deletes the previous run's files (the engine contract).
 */
public abstract class CheckReachabilityTask extends DefaultTask {

    /** The main source set's classes directory (exactly one, see the plugin). */
    @Internal
    public abstract DirectoryProperty getAppClasses();

    /** The resolved runtime classpath; written to a file for the engine. */
    @InputFiles
    public abstract ConfigurableFileCollection getClasspathJars();

    @Input
    public abstract Property<String> getBomFile();

    @Input
    public abstract Property<String> getOsvDir();

    @Input
    public abstract Property<String> getExpectedOsvChecksum();

    @Input
    public abstract Property<String> getMappings();

    @Input
    public abstract ListProperty<String> getEntryPoints();

    @Input
    public abstract ListProperty<String> getCallbackInterfaces();

    @Input
    public abstract Property<Boolean> getCha();

    @Input
    public abstract Property<Boolean> getPointerAnalysis();

    @Input
    public abstract Property<String> getFormats();

    /** Base name for the reports; resolved against the build directory unless absolute. */
    @Input
    public abstract Property<String> getReportBase();

    @TaskAction
    public void check() {
        if (getBomFile().get().isBlank()) {
            throw new GradleException("checkReachability: the reachability extension needs bomFile "
                    + "(point it at your CycloneDX bom.json or an SPDX 2.x document)");
        }
        if (getOsvDir().get().isBlank()) {
            throw new GradleException("checkReachability: the reachability extension needs osvDir");
        }
        if (getCha().get() && getPointerAnalysis().get()) {
            throw new GradleException("checkReachability: cha and pointerAnalysis are mutually exclusive");
        }

        Path cpFile = writeClasspathFile();
        Path reportBase = reportBase();

        DiagnosticSink sink = new DiagnosticSink() {
            @Override
            public void out(String line) {
                getProject().getLogger().lifecycle(line);
            }

            @Override
            public void err(String line) {
                getProject().getLogger().error(line);
            }
        };
        int exitCode = AnalyzerEngine.analyze(request(cpFile), reportBase,
                parseFormats(), false, sink).exitCode();

        if (exitCode == 1) {
            throw new GradleException("reachable vulnerabilities found — see " + reportFiles(reportBase));
        }
        if (exitCode != 0) {
            throw new GradleException("reachability analysis failed (exit " + exitCode
                    + "); see the console output above");
        }
    }

    private AnalysisRequest request(Path cpFile) {
        CallGraphPolicy policy = getPointerAnalysis().get() ? CallGraphPolicy.SPARK
                : getCha().get() ? CallGraphPolicy.CHA : CallGraphPolicy.RTA;
        return new AnalysisRequest(
                getAppClasses().get().getAsFile().toPath(),
                cpFile,
                Path.of(getBomFile().get()),
                Path.of(getOsvDir().get()),
                present(getExpectedOsvChecksum()),
                present(getMappings()).map(Path::of),
                policy,
                getEntryPoints().get(),
                CallbackInterfaceSpecs.parse(getCallbackInterfaces().get()),
                Optional.empty());
    }

    /** Unset optionals read as empty — the plugin gives every property a convention. */
    private static Optional<String> present(Property<String> property) {
        String value = property.getOrElse("").trim();
        return value.isEmpty() ? Optional.empty() : Optional.of(value);
    }

    private Path reportBase() {
        Path base = Path.of(getReportBase().get());
        if (!base.isAbsolute()) {
            base = getProject().getLayout().getBuildDirectory().get().getAsFile().toPath().resolve(base);
        }
        return base;
    }

    /** The runtime classpath as the engine's newline-separated jar list; null when empty. */
    private Path writeClasspathFile() {
        List<String> jars = new ArrayList<>();
        for (File jar : getClasspathJars()) {
            jars.add(jar.getAbsolutePath());
        }
        if (jars.isEmpty()) {
            return null;
        }
        Path file = getProject().getLayout().getBuildDirectory().file("reachability-cp.txt")
                .get().getAsFile().toPath();
        try {
            Files.write(file, jars);
            return file;
        } catch (IOException e) {
            throw new GradleException("cannot write the classpath file " + file + ": " + e.getMessage());
        }
    }

    private List<ReportFormat> parseFormats() {
        List<ReportFormat> formats = new ArrayList<>();
        for (String token : getFormats().get().split(",")) {
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

    private String reportFiles(Path reportBase) {
        List<String> files = new ArrayList<>();
        for (ReportFormat format : parseFormats()) {
            files.add(reportBase + format.suffix());
        }
        return String.join(", ", files);
    }
}
