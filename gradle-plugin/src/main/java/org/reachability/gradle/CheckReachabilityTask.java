package org.reachability.gradle;

import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.file.ConfigurableFileCollection;
import org.gradle.api.file.DirectoryProperty;
import org.gradle.api.file.RegularFile;
import org.gradle.api.file.RegularFileProperty;
import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.CacheableTask;
import org.gradle.api.tasks.Classpath;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.InputDirectory;
import org.gradle.api.tasks.InputFile;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFiles;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
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

/**
 * A10 (M7e), M8: runs the reachability analysis on the project's main
 * source set - compiled classes + resolved runtime classpath - in-process
 * and fails the build when any SBOM vulnerability is reachable (engine
 * exit 1), or when the run itself was unusable (exit 2/3). M8: the task is
 * cacheable - content-sensitive inputs (app classes, classpath jars,
 * SBOM/OSV/mappings content) and declared outputs (the reports and the
 * classpath file) drive both the up-to-date check and the build cache, so
 * the analysis does not re-run when nothing changed. The analysis runs in
 * the daemon (Gradle 9.8 exposes no public worker-executor accessor), so a
 * huge graph needs the daemon's heap raised via org.gradle.jvmargs.
 */
@CacheableTask
public abstract class CheckReachabilityTask extends DefaultTask {

    /** The main source set's classes directory (exactly one, see the plugin). */
    @InputDirectory
    @PathSensitive(PathSensitivity.NONE)
    public abstract DirectoryProperty getAppClasses();

    /** The resolved runtime classpath; written to a file for the engine. */
    @Classpath
    public abstract ConfigurableFileCollection getClasspathJars();

    @Input
    public abstract Property<String> getBomFile();

    @Input
    public abstract Property<String> getOsvDir();

    @Input
    public abstract Property<String> getExpectedOsvChecksum();

    @Input
    public abstract Property<String> getMappings();

    /** The SBOM file content; the path string alone would miss content edits. */
    @InputFile
    @Optional
    @PathSensitive(PathSensitivity.NONE)
    public abstract RegularFileProperty getBomFileContent();

    /** The OSV directory content; a record added in place re-runs the check. */
    @InputDirectory
    @Optional
    @PathSensitive(PathSensitivity.NONE)
    public abstract DirectoryProperty getOsvDirContent();

    /** The mappings file content. */
    @InputFile
    @Optional
    @PathSensitive(PathSensitivity.NONE)
    public abstract RegularFileProperty getMappingsContent();

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

    /** The written reports and classpath file; declared so the task is cacheable. */
    @OutputFiles
    public List<RegularFile> getWrittenFiles() {
        List<RegularFile> outputs = new ArrayList<>();
        if (!getClasspathJars().isEmpty()) {
            outputs.add(getProject().getLayout().getBuildDirectory().file("reachability-cp.txt").get());
        }
        for (ReportFormat format : parseFormats()) {
            outputs.add(reportFile(format));
        }
        return outputs;
    }

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
        List<ReportFormat> formats = parseFormats();

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
        int exitCode = AnalyzerEngine.analyze(request(cpFile), reportBase, formats, false, sink).exitCode();

        if (exitCode == 1) {
            throw new GradleException("reachable vulnerabilities found - see " + reportFiles(reportBase, formats));
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
                Path.of(resolve(getBomFile().get())),
                Path.of(resolve(getOsvDir().get())),
                present(getExpectedOsvChecksum()),
                present(getMappings()).map(this::resolve).map(Path::of),
                policy,
                getEntryPoints().get(),
                CallbackInterfaceSpecs.parse(getCallbackInterfaces().get()),
                java.util.Optional.empty());
    }

    /** Unset optionals read as empty - the plugin gives every property a convention. */
    private static java.util.Optional<String> present(Property<String> property) {
        String value = property.getOrElse("").trim();
        return value.isEmpty() ? java.util.Optional.empty() : java.util.Optional.of(value);
    }

    /**
     * Relative paths resolve against the project directory; absolute paths
     * pass through; the result is lexically normalized. (JDK 25's two-arg
     * File constructor also joins absolute children, so Path.resolve is used.)
     */
    private String resolve(String path) {
        Path p = Path.of(path);
        Path resolved = p.isAbsolute() ? p : getProject().getProjectDir().toPath().resolve(p);
        return resolved.normalize().toString();
    }

    private Path classpathFile() {
        return getProject().getLayout().getBuildDirectory().file("reachability-cp.txt").get().getAsFile().toPath();
    }

    private Path reportBase() {
        Path base = Path.of(getReportBase().get());
        if (!base.isAbsolute()) {
            base = getProject().getLayout().getBuildDirectory().get().getAsFile().toPath().resolve(base);
        }
        return base;
    }

    /** The engine's report location for the format: {@code <base><suffix>}. */
    private RegularFile reportFile(ReportFormat format) {
        Path base = reportBase();
        Path file = base.getParent().resolve(base.getFileName() + format.suffix());
        return getProject().getLayout().file(getProject().provider(() -> file.toFile())).get();
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
        Path file = classpathFile();
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

    private String reportFiles(Path reportBase, List<ReportFormat> formats) {
        List<String> files = new ArrayList<>();
        for (ReportFormat format : formats) {
            files.add(reportBase + format.suffix());
        }
        return String.join(", ", files);
    }
}
