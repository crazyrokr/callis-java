package org.reachability.gradle;

import javax.inject.Inject;

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
import org.gradle.api.tasks.Internal;
import org.gradle.api.tasks.Optional;
import org.gradle.api.tasks.OutputFiles;
import org.gradle.api.tasks.PathSensitive;
import org.gradle.api.tasks.PathSensitivity;
import org.gradle.api.tasks.TaskAction;
import org.gradle.workers.WorkQueue;
import org.gradle.workers.WorkerExecutor;
import org.gradle.workers.WorkerExecutionException;
import org.reachability.analyzer.engine.ReportFormat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;

/**
 * A10 (M7e), M8, M9: runs the reachability analysis on the project's main
 * source set - compiled classes + resolved runtime classpath - and fails
 * the build when any SBOM vulnerability is reachable (engine exit 1), or
 * when the run itself was unusable (exit 2/3). M8: the task is cacheable -
 * content-sensitive inputs (app classes, classpath jars, SBOM/OSV/mappings
 * content) and declared outputs (the reports and the classpath file) drive
 * both the up-to-date check and the build cache, so the analysis does not
 * re-run when nothing changed. M9: the analysis runs in a forked worker
 * process (process isolation, maxHeapSize heap) instead of the daemon;
 * Gradle 9.8 has no Project accessor for the worker executor, so the task
 * receives it via @Inject, and it delivers configured parameters to a work
 * action only when the action implements the internal ProvidesWorkResult
 * marker with an @Inject (WorkParameters, InstanceGenerator) constructor
 * (recorded in A10).
 */
@CacheableTask
public abstract class CheckReachabilityTask extends DefaultTask {

    /** Injected by the task decorator: 9.8 has no Project accessor for the worker executor. */
    @Inject
    public abstract WorkerExecutor getWorkerExecutor();

    /** Max heap of the forked analysis worker; a resource setting, not a verdict input. */
    @Internal
    public abstract Property<String> getMaxHeapSize();

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

        runInForkedWorker(cpFile, reportBase);
    }

    /**
     * The engine runs in a forked worker process so a huge graph cannot
     * starve the daemon; the worker's failures are unwrapped to the
     * task's own messages (the reports list, the exit code).
     */
    private void runInForkedWorker(Path cpFile, Path reportBase) {
        WorkQueue queue = getWorkerExecutor().processIsolation(spec ->
                spec.getForkOptions().setMaxHeapSize(getMaxHeapSize().get()));
        queue.submit(ReachabilityWorkAction.class, params -> configure(params, cpFile, reportBase));
        try {
            queue.await();
        } catch (WorkerExecutionException e) {
            throw unwrap(e);
        }
    }

    private void configure(ReachabilityWorkAction.Params params, Path cpFile, Path reportBase) {
        params.setAppClasses(getAppClasses().get().getAsFile().getAbsolutePath());
        params.setClasspathFile(cpFile == null ? "" : cpFile.toString());
        params.setBomFile(resolve(getBomFile().get()));
        params.setOsvDir(resolve(getOsvDir().get()));
        params.setExpectedOsvChecksum(present(getExpectedOsvChecksum()).orElse(""));
        params.setMappings(present(getMappings()).map(this::resolve).orElse(""));
        params.setPolicyName(getPointerAnalysis().get() ? "SPARK" : getCha().get() ? "CHA" : "RTA");
        params.setFormats(getFormats().get());
        params.setReportBase(reportBase.toString());
        params.setEntryPoints(new ArrayList<>(getEntryPoints().get()));
        params.setCallbackInterfaces(new ArrayList<>(getCallbackInterfaces().get()));
    }

    /**
     * The worker wraps failures in a multi-cause exception; the task's own
     * GradleException (with the report file names) must reach the build
     * output, so the first non-wrapping GradleException in the chain wins.
     */
    private static GradleException unwrap(WorkerExecutionException e) {
        Deque<Throwable> pending = new ArrayDeque<>();
        pending.push(e);
        while (!pending.isEmpty()) {
            Throwable t = pending.pop();
            if (t instanceof GradleException && !(t instanceof WorkerExecutionException)) {
                return (GradleException) t;
            }
            if (t.getCause() != null) {
                pending.push(t.getCause());
            }
            for (Throwable suppressed : t.getSuppressed()) {
                pending.push(suppressed);
            }
        }
        return e;
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
}
