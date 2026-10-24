package org.reachability.gradle

import org.gradle.testkit.runner.BuildResult
import org.gradle.testkit.runner.GradleRunner

import java.nio.file.Files
import java.nio.file.Path

/**
 * TestKit fixture project for the plugin specs.
 *
 * The specs cannot build projects in-process with ProjectBuilder: under the
 * Groovy 6.0.0 test classpath, any Groovy dynamic dispatch on a DefaultProject
 * reaches the Gradle API's CallInterceptorRegistry, which loads
 * org.codehaus.groovy.runtime.callsite.CallSite — a class Groovy 6 removed —
 * so it throws instead. TestKit builds run with the distribution's own Groovy,
 * so the fixtures work (the same pattern tickonomics uses for its plugin
 * specs).
 *
 * A fixture carries a dumpWiring task that reads the live extension and the
 * realized checkReachability task and writes their values to
 * wiring-dump.txt, so a spec asserts exactly the values the original
 * in-project assertions checked.
 */
final class FixtureProject {

    private static final String STUBLIB_JAR =
            "../core/src/test/resources/fixtures/mini-app/stublib.jar"

    private static final String DUMP_TASK = '''
task dumpWiring {
    doLast {
        def ext = project.extensions.getByName('reachability')
        def t = project.tasks.getByName('checkReachability')
        def main = project.sourceSets.main
        def dump = [
            'task.exists=true',
            'extension.exists=true',
            'extension.formats=' + ext.formats.get(),
            'extension.cha=' + ext.cha.get(),
            'extension.pointerAnalysis=' + ext.pointerAnalysis.get(),
            'extension.entryPoints=' + ext.entryPoints.get(),
            'extension.callbackInterfaces=' + ext.callbackInterfaces.get(),
            'extension.maxHeapSize=' + ext.maxHeapSize.get(),
            'extension.osvDir=' + ext.osvDir.get(),
            'extension.bomFile=' + ext.bomFile.get(),
            'extension.expectedOsvChecksum=' + ext.expectedOsvChecksum.get(),
            'extension.mappings=' + ext.mappings.get(),
            'task.group=' + t.group,
            'task.maxHeapSize=' + t.maxHeapSize.get(),
            'task.osvDir=' + t.osvDir.get(),
            'task.bomFile=' + t.bomFile.get(),
            'task.expectedOsvChecksum=' + t.expectedOsvChecksum.get(),
            'task.mappings=' + t.mappings.get(),
            'task.pointerAnalysis=' + t.pointerAnalysis.get(),
            'task.cha=' + t.cha.get(),
            'task.formats=' + t.formats.get(),
            'task.entryPoints=' + t.entryPoints.get(),
            'task.dependsOn=' + t.dependsOn.collect { it instanceof org.gradle.api.provider.Provider ? it.get().name : it },
            'task.classpathJars=' + t.classpathJars.files.collect { it.absolutePath }.sort().join('|'),
            'runtimeClasspath=' + project.configurations.runtimeClasspath.files.collect { it.absolutePath }.sort().join('|'),
            'task.appClasses=' + t.appClasses.get().asFile.absolutePath,
            'mainClasses=' + main.output.classesDirs.files.iterator().next().absolutePath
        ]
        new File(project.projectDir, 'wiring-dump.txt').text = dump.join('\\n')
    }
}
'''

    private final Path dir

    private FixtureProject(Path dir) {
        this.dir = dir
    }

    /** A fixture with the java plugin, the plugin under test, the stublib dependency and the given reachability block. */
    static FixtureProject withJavaPlugin(Path dir, String reachabilityBlock) {
        FixtureProject fixture = new FixtureProject(dir)
        Files.createDirectories(dir)
        Files.writeString(dir.resolve("settings.gradle"), "rootProject.name = 'fixture-app'\n")
        Files.writeString(dir.resolve("build.gradle"),
                "plugins {\n    id 'java'\n    id 'org.crazyrock.callis'\n}\n" +
                        "dependencies {\n    implementation files('" + new File(STUBLIB_JAR).absolutePath + "')\n}\n" +
                        reachabilityBlock +
                        DUMP_TASK)
        Files.createDirectories(dir.resolve("src/main/java/fixture"))
        Files.writeString(dir.resolve("src/main/java/fixture/App.java"),
                "package fixture;\n" +
                        "public class App {\n" +
                        "    public static void main(String[] args) {\n" +
                        "        new stublib.Stub().danger();\n" +
                        "    }\n" +
                        "}\n")
        return fixture
    }

    /** A fixture with only the plugin under test; applying it must fail. */
    static FixtureProject withoutJavaPlugin(Path dir) {
        FixtureProject fixture = new FixtureProject(dir)
        Files.createDirectories(dir)
        Files.writeString(dir.resolve("settings.gradle"), "rootProject.name = 'fixture-app'\n")
        Files.writeString(dir.resolve("build.gradle"),
                "plugins {\n    id 'org.crazyrock.callis'\n}\n")
        return fixture
    }

    /** Runs the given tasks in the fixture and requires the build to succeed. */
    BuildResult run(String... args) {
        return GradleRunner.create()
                .withProjectDir(dir.toFile())
                .withPluginClasspath()
                .withArguments(*args)
                .build()
    }

    /** Runs the given tasks in the fixture and requires the build to fail. */
    BuildResult runFailing(String... args) {
        return GradleRunner.create()
                .withProjectDir(dir.toFile())
                .withPluginClasspath()
                .withArguments(*args)
                .buildAndFail()
    }

    /** Runs dumpWiring and returns the dumped extension/task values. */
    Map<String, String> wiringDump() {
        run("dumpWiring")
        Map<String, String> values = [:]
        Files.readAllLines(dir.resolve("wiring-dump.txt")).each { line ->
            int eq = line.indexOf('=')
            values.put(line.substring(0, eq), line.substring(eq + 1))
        }
        return values
    }
}
