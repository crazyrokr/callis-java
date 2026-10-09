package org.reachability.maven;

import org.apache.maven.artifact.Artifact;
import org.apache.maven.artifact.DefaultArtifact;
import org.apache.maven.artifact.handler.DefaultArtifactHandler;
import org.apache.maven.model.Build;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * M7e (A10): the reachability:check goal against a hand-built MavenProject
 * (app classes compiled in-test against the core fixture's stublib.jar, the
 * core fixtures as SBOM/OSV/mappings). Plain JUnit 5 instead of the
 * JUnit-4-only maven-plugin-testing-harness (recorded deviation).
 */
class ReachabilityCheckMojoTest {

    private static final Path STUBLIB_JAR =
            Path.of("../core/src/test/resources/fixtures/mini-app/stublib.jar");
    private static final Path BOM_MINI =
            Path.of("../core/src/test/resources/fixtures/bom-mini.json");
    private static final Path OSV_MINI =
            Path.of("../core/src/test/resources/fixtures/osv-mini");
    private static final Path MAPPINGS =
            Path.of("../core/src/test/resources/fixtures/mappings/valid.json");

    @TempDir
    Path buildDir;

    @Test
    void givenAVulnerableProjectWhenCheckRunsThenTheMojoFailsAndTheReportsAreWritten() throws Exception {
        // given: app classes that call stublib.Stub.danger, stublib.jar on the runtime classpath
        MavenProject project = project(compileApp("danger"), STUBLIB_JAR.toFile());
        ReachabilityCheckMojo mojo = mojo(project);

        // when / then
        MojoExecutionException e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(e.getMessage().contains("reachable vulnerabilities"), e.getMessage());
        assertTrue(Files.exists(buildDir.resolve("reachability-report.json")));
        assertTrue(Files.exists(buildDir.resolve("reachability-report.junit.xml")));
    }

    @Test
    void givenAnOsvDirectoryThatMatchesNothingWhenCheckRunsThenTheMojoSucceedsAndWritesNoReports() throws Exception {
        // given: the same project, but an OSV directory with no matching records
        Files.createDirectories(buildDir.resolve("osv-empty"));
        MavenProject project = project(compileApp("safe"), STUBLIB_JAR.toFile());
        ReachabilityCheckMojo mojo = mojo(project);
        mojo.osvDir = buildDir.resolve("osv-empty").toFile();

        // when / then: no exception, and no report files from the zero-candidate run
        mojo.execute();
        assertFalse(Files.exists(buildDir.resolve("reachability-report.json")));
        assertFalse(Files.exists(buildDir.resolve("reachability-report.junit.xml")));
    }

    @Test
    void givenNoSbomFileWhenCheckRunsThenTheMojoFailsWithTheUsageError() throws Exception {
        // given
        MavenProject project = project(new File(buildDir.toFile(), "no-classes"));
        ReachabilityCheckMojo mojo = new ReachabilityCheckMojo();
        mojo.project = project;
        mojo.osvDir = OSV_MINI.toFile();

        // when / then
        MojoExecutionException e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(e.getMessage().contains("sbomFile"), e.getMessage());
    }

    @Test
    void givenBothChaAndPointerAnalysisWhenCheckRunsThenTheMojoFails() throws Exception {
        // given
        MavenProject project = project(new File(buildDir.toFile(), "no-classes"));
        ReachabilityCheckMojo mojo = mojo(project);
        mojo.cha = true;
        mojo.pointerAnalysis = true;

        // when / then
        MojoExecutionException e = assertThrows(MojoExecutionException.class, mojo::execute);
        assertTrue(e.getMessage().contains("mutually exclusive"), e.getMessage());
    }

    private MavenProject project(File appClasses, File... classpathJars) {
        MavenProject project = new MavenProject();
        project.setGroupId("test");
        project.setArtifactId("fixture-app");
        project.setVersion("1.0");
        Build build = new Build();
        build.setDirectory(buildDir.toAbsolutePath().toString());
        build.setOutputDirectory(appClasses.getAbsolutePath());
        project.setBuild(build);
        for (File jar : classpathJars) {
            DefaultArtifactHandler handler = new DefaultArtifactHandler("jar");
            handler.setAddedToClasspath(true);
            Artifact artifact = new DefaultArtifact("stublib", "stublib", "1.0",
                    Artifact.SCOPE_COMPILE, "jar", null, handler);
            artifact.setFile(jar);
            project.getArtifacts().add(artifact);
        }
        return project;
    }

    private ReachabilityCheckMojo mojo(MavenProject project) {
        ReachabilityCheckMojo mojo = new ReachabilityCheckMojo();
        mojo.sbomFile = BOM_MINI.toFile();
        mojo.osvDir = OSV_MINI.toFile();
        mojo.mappings = MAPPINGS.toFile();
        mojo.formats = "json,junitxml";
        mojo.project = project;
        return mojo;
    }

    /** Compiles a one-method app (the given stublib call) against stublib.jar. */
    private File compileApp(String stubMethod) throws Exception {
        Path classesDir = buildDir.resolve("classes");
        Files.createDirectories(classesDir);
        Path source = classesDir.resolve("App.java");
        Files.writeString(source,
                "public class App {\n"
                        + "    public static void main(String[] args) {\n"
                        + "        new stublib.Stub()." + stubMethod + "();\n"
                        + "    }\n"
                        + "}\n");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        int rc = compiler.run(null, null, null,
                "-cp", STUBLIB_JAR.toAbsolutePath().toString(),
                "-d", classesDir.toString(),
                source.toString());
        assertTrue(rc == 0, "fixture app must compile against stublib.jar");
        return classesDir.toFile();
    }
}
