package org.reachability.gradle

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * M7e (A10): TestKit functional tests — a fixture project (main() that
 * calls the core fixture's stublib.Stub.danger, stublib.jar on the
 * runtime classpath, the core fixtures as SBOM/OSV/mappings) run through
 * the real plugin: the vulnerable pin fails checkReachability with the
 * reports on disk, the CHA flag changes nothing for the verdict, and a
 * zero-candidate OSV directory succeeds.
 */
class CheckReachabilityTaskFunctionalSpec extends Specification {

    private static final String STUBLIB_JAR =
            "../core/src/test/resources/fixtures/mini-app/stublib.jar"
    private static final String BOM_MINI =
            "../core/src/test/resources/fixtures/bom-mini.json"
    private static final String OSV_MINI =
            "../core/src/test/resources/fixtures/osv-mini"
    private static final String MAPPINGS =
            "../core/src/test/resources/fixtures/mappings/valid.json"

    @TempDir
    Path projectDir

    private void writeFixtureProject(String osvDir, boolean cha) {
        Files.writeString(projectDir.resolve("settings.gradle"), "rootProject.name = 'fixture-app'\n")
        Files.writeString(projectDir.resolve("build.gradle"),
                "plugins {\n    id 'java'\n    id 'org.reachability'\n}\n" +
                        "dependencies {\n    implementation files('" + new File(STUBLIB_JAR).absolutePath + "')\n}\n" +
                        "reachability {\n" +
                        "    bomFile = '" + new File(BOM_MINI).absolutePath + "'\n" +
                        "    osvDir = '" + osvDir + "'\n" +
                        "    mappings = '" + new File(MAPPINGS).absolutePath + "'\n" +
                        (cha ? "    cha = true\n" : "") +
                        "}\n")
        Files.createDirectories(projectDir.resolve("src/main/java/fixture"))
        Files.writeString(projectDir.resolve("src/main/java/fixture/App.java"),
                "package fixture;\n" +
                        "public class App {\n" +
                        "    public static void main(String[] args) {\n" +
                        "        new stublib.Stub().danger();\n" +
                        "    }\n" +
                        "}\n")
    }

    private GradleRunner runner(String... args) {
        GradleRunner.create()
                .withProjectDir(projectDir.toFile())
                .withPluginClasspath()
                .withArguments(*args)
    }

    def "given a vulnerable project when checkReachability runs then the task fails and the reports are written"() {
        given:
        writeFixtureProject(new File(OSV_MINI).absolutePath, false)

        when:
        def result = runner("checkReachability", "--stacktrace").buildAndFail()
        println result.output

        then: "the reachable vulnerability fails the task; the reports exist next to the build directory"
        result.output.contains("VULN-POS")
        result.output.contains("REACHABLE")
        result.output.contains("fixture.App#main -> stublib.Stub#danger")
        Files.exists(projectDir.resolve("build/reachability-report.json"))
        Files.exists(projectDir.resolve("build/reachability-report.junit.xml"))
    }

    def "given the same project with the cha policy when checkReachability runs then the verdict holds"() {
        given:
        writeFixtureProject(new File(OSV_MINI).absolutePath, true)

        when:
        def result = runner("checkReachability", "--stacktrace").buildAndFail()
        println result.output

        then:
        result.output.contains("VULN-POS")
        result.output.contains("REACHABLE")
        result.output.contains("fixture.App#main -> stublib.Stub#danger")
    }

    def "given a project whose osv directory matches nothing when checkReachability runs then the task succeeds"() {
        given:
        Files.createDirectories(projectDir.resolve("osv-empty"))
        writeFixtureProject(projectDir.resolve("osv-empty").toAbsolutePath().toString(), false)

        when:
        def result = runner("checkReachability").build()

        then:
        result.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        result.output.contains("No vulnerability candidates")
    }

    def "given a project with no bomFile configured when checkReachability runs then the task fails with the usage error"() {
        given:
        Files.writeString(projectDir.resolve("settings.gradle"), "rootProject.name = 'fixture-app'\n")
        Files.writeString(projectDir.resolve("build.gradle"),
                "plugins {\n    id 'java'\n    id 'org.reachability'\n}\n" +
                        "dependencies {\n    implementation files('" + new File(STUBLIB_JAR).absolutePath + "')\n}\n" +
                        "reachability {\n" +
                        "    osvDir = '" + new File(OSV_MINI).absolutePath + "'\n}\n")
        Files.createDirectories(projectDir.resolve("src/main/java/fixture"))
        Files.writeString(projectDir.resolve("src/main/java/fixture/App.java"),
                "package fixture;\n" +
                        "public class App {\n" +
                        "    public static void main(String[] args) {\n" +
                        "        new stublib.Stub().safe();\n" +
                        "    }\n" +
                        "}\n")

        when:
        def result = runner("checkReachability", "--stacktrace").buildAndFail()
        println result.output

        then:
        result.output.contains("bomFile")
    }
}
