package org.reachability.maven;

import org.apache.maven.artifact.DependencyResolutionRequiredException;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugins.annotations.ResolutionScope;
import org.apache.maven.project.MavenProject;
import org.crazyrock.callis.engine.AnalysisRequest;
import org.crazyrock.callis.engine.AnalyzerEngine;
import org.crazyrock.callis.engine.CallGraphPolicy;
import org.crazyrock.callis.engine.CallbackInterfaceSpecs;
import org.crazyrock.callis.engine.DiagnosticSink;
import org.crazyrock.callis.engine.ReportFormat;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * M7e (A10): the reachability check as a Maven goal. Runs the core engine
 * in-process on the project's built classes ({@code target/classes}) plus the
 * resolved runtime classpath, against the project's SBOM and a local OSV
 * snapshot. Fails the build with a {@link MojoExecutionException} when any
 * vulnerability is reachable (engine exit 1) or when the run itself was
 * unusable (exit 2/3); reports go to
 * {@code target/reachability-report.*}.
 *
 * <p>Typical invocation (after the project's CycloneDX plugin wrote the
 * SBOM at package time):
 * {@code mvn org.reachability:reachability-maven-plugin:0.1.0-SNAPSHOT:check
 * -Dreachability.sbomFile=target/bom.json -Dreachability.osvDir=osv-maven}.
 *
 * <p>Fields are package-private so the plain JUnit 5 tests can drive the goal
 * without a Maven session.
 */
@Mojo(name = "check", defaultPhase = LifecyclePhase.VERIFY,
        requiresDependencyResolution = ResolutionScope.RUNTIME, threadSafe = true)
public class ReachabilityCheckMojo extends AbstractMojo {

    @Parameter(property = "reachability.sbomFile")
    File sbomFile;

    @Parameter(property = "reachability.osvDir")
    File osvDir;

    @Parameter(property = "reachability.mappings")
    File mappings;

    @Parameter(property = "reachability.expectedOsvChecksum")
    String expectedOsvChecksum;

    @Parameter(property = "reachability.entryPoints")
    List<String> entryPoints;

    @Parameter(property = "reachability.callbackInterfaces")
    List<String> callbackInterfaces;

    @Parameter(property = "reachability.cha", defaultValue = "false")
    boolean cha;

    @Parameter(property = "reachability.pointerAnalysis", defaultValue = "false")
    boolean pointerAnalysis;

    @Parameter(property = "reachability.formats", defaultValue = "json,junitxml")
    String formats;

    @Parameter(defaultValue = "${project}", readonly = true, required = true)
    MavenProject project;

    public void execute() throws MojoExecutionException {
        if (sbomFile == null) {
            throw new MojoExecutionException("reachability:check needs -Dreachability.sbomFile=<path> "
                    + "(the project's CycloneDX bom.json or an SPDX 2.x document)");
        }
        if (osvDir == null) {
            throw new MojoExecutionException("reachability:check needs -Dreachability.osvDir=<path> "
                    + "(a directory with local OSV Maven records)");
        }
        if (cha && pointerAnalysis) {
            throw new MojoExecutionException("reachability.cha and reachability.pointerAnalysis "
                    + "are mutually exclusive");
        }

        List<ReportFormat> parsedFormats = parseFormats();
        Path cpFile = writeClasspathFile();
        Path reportBase = new File(project.getBuild().getDirectory(), "reachability-report").toPath();

        DiagnosticSink sink = new DiagnosticSink() {
            @Override
            public void out(String line) {
                getLog().info(line);
            }

            @Override
            public void err(String line) {
                getLog().error(line);
            }
        };
        int exitCode = AnalyzerEngine.analyze(request(cpFile), reportBase,
                parsedFormats, false, sink).exitCode();

        if (exitCode == 1) {
            throw new MojoExecutionException("reachable vulnerabilities found - see "
                    + reportFiles(reportBase, parsedFormats));
        }
        if (exitCode != 0) {
            throw new MojoExecutionException("reachability analysis failed (exit " + exitCode
                    + "); see the console output above");
        }
    }

    private AnalysisRequest request(Path cpFile) {
        CallGraphPolicy policy = pointerAnalysis ? CallGraphPolicy.SPARK
                : cha ? CallGraphPolicy.CHA : CallGraphPolicy.RTA;
        return new AnalysisRequest(
                Path.of(project.getBuild().getOutputDirectory()),
                cpFile,
                sbomFile.toPath(),
                osvDir.toPath(),
                present(expectedOsvChecksum),
                mappings == null ? Optional.empty() : Optional.of(mappings.toPath()),
                policy,
                entryPoints == null ? List.of() : entryPoints,
                CallbackInterfaceSpecs.parse(callbackInterfaces == null ? List.of() : callbackInterfaces),
                Optional.empty());
    }

    /** Null/blank optionals read as empty. */
    private static Optional<String> present(String value) {
        if (value == null) {
            return Optional.empty();
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? Optional.empty() : Optional.of(trimmed);
    }

    /** The resolved runtime classpath as the engine's newline-separated jar list; null when empty. */
    private Path writeClasspathFile() throws MojoExecutionException {
        List<String> jars;
        try {
            jars = project.getRuntimeClasspathElements();
        } catch (DependencyResolutionRequiredException e) {
            throw new MojoExecutionException("the project's runtime classpath is not resolved: "
                    + e.getMessage());
        }
        if (jars.isEmpty()) {
            return null;
        }
        Path file = new File(project.getBuild().getDirectory(), "reachability-cp.txt").toPath();
        try {
            Files.write(file, jars);
            return file;
        } catch (IOException e) {
            throw new MojoExecutionException("cannot write the classpath file " + file + ": " + e.getMessage());
        }
    }

    private List<ReportFormat> parseFormats() throws MojoExecutionException {
        String spec = formats == null ? "json,junitxml" : formats;
        List<ReportFormat> parsed = new ArrayList<>();
        for (String token : spec.split(",")) {
            ReportFormat format = token.equals("json") ? ReportFormat.JSON
                    : token.equals("junitxml") ? ReportFormat.JUNITXML
                    : token.equals("sarif") ? ReportFormat.SARIF
                    : null;
            if (format == null) {
                throw new MojoExecutionException("reachability:check: unknown report format '" + token
                        + "' (expected json, junitxml, sarif)");
            }
            parsed.add(format);
        }
        return parsed;
    }

    private String reportFiles(Path reportBase, List<ReportFormat> parsedFormats) {
        List<String> files = new ArrayList<>();
        for (ReportFormat format : parsedFormats) {
            files.add(reportBase + format.suffix());
        }
        return String.join(", ", files);
    }
}
