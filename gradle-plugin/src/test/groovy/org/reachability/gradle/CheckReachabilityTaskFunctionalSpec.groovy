package org.reachability.gradle

import org.gradle.testkit.runner.GradleRunner
import org.gradle.testkit.runner.TaskOutcome
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * M7e/M8 (A10): TestKit functional tests - a fixture project (main() that
 * calls the core fixture's stublib.Stub.danger, stublib.jar on the
 * runtime classpath, the core fixtures as SBOM/OSV/mappings) run through
 * the real plugin: the vulnerable pin fails checkReachability with the
 * reports on disk, the CHA flag changes nothing for the verdict, and a
 * zero-candidate OSV directory succeeds. M8 adds the up-to-date pins: a
 * changed app class, an OSV record added in place, and an SBOM content
 * edit each re-run the task, and the build cache restores the task's
 * outputs for identical content in a new project directory.
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

    // --- M8: up-to-date and build-cache behavior ---------------------------
    // A safe project (App.main calls Stub.safe) against osv-mini's VULN-POS:
    // one UNREACHABLE candidate, exit 0, reports written.

    private void writeSafeFixture(String bomFile, String osvDir, boolean osvHasRecords) {
        Files.createDirectories(projectDir.resolve(osvDir))
        if (osvHasRecords) {
            Files.copy(Path.of(new File(OSV_MINI).absolutePath, "VULN-POS.json"),
                    projectDir.resolve(osvDir).resolve("VULN-POS.json"))
        }
        Files.writeString(projectDir.resolve("settings.gradle"), "rootProject.name = 'fixture-app'\n")
        Files.writeString(projectDir.resolve("build.gradle"),
                "plugins {\n    id 'java'\n    id 'org.reachability'\n}\n" +
                        "dependencies {\n    implementation files('" + new File(STUBLIB_JAR).absolutePath + "')\n}\n" +
                        "reachability {\n" +
                        "    bomFile = '" + bomFile + "'\n" +
                        "    osvDir = '" + osvDir + "'\n" +
                        "    mappings = '" + new File(MAPPINGS).absolutePath + "'\n" +
                        "}\n")
        Files.createDirectories(projectDir.resolve("src/main/java/fixture"))
        Files.writeString(projectDir.resolve("src/main/java/fixture/App.java"),
                "package fixture;\n" +
                        "public class App {\n" +
                        "    public static void main(String[] args) {\n" +
                        "        new stublib.Stub().safe();\n" +
                        "    }\n" +
                        "}\n")
    }

    private GradleRunner runnerIn(Path dir, String... args) {
        GradleRunner.create()
                .withProjectDir(dir.toFile())
                .withPluginClasspath()
                .withArguments(*args)
    }

    private void copyProjectTo(Path target) {
        Files.createDirectories(target)
        for (String name in ["settings.gradle", "build.gradle", "bom.json"]) {
            Files.copy(projectDir.resolve(name), target.resolve(name))
        }
        copyRecursively(projectDir.resolve("src"), target.resolve("src"))
        copyRecursively(projectDir.resolve("osv-mini"), target.resolve("osv-mini"))
    }

    private void copyRecursively(Path source, Path target) {
        Files.walk(source).toList().each { Path file ->
            Path destination = target.resolve(source.relativize(file).toString())
            if (Files.isDirectory(file)) {
                Files.createDirectories(destination)
            } else {
                Files.createDirectories(destination.parent)
                Files.copy(file, destination)
            }
        }
    }

    def "given a safe project when the app starts calling the vulnerable method then the task re-runs and fails"() {
        given:
        writeSafeFixture(new File(BOM_MINI).absolutePath, "osv-mini", true)

        when:
        def first = runner("checkReachability").build()
        println first.output

        then:
        first.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        Files.exists(projectDir.resolve("build/reachability-report.json"))

        when: "the app now calls the vulnerable method"
        Files.writeString(projectDir.resolve("src/main/java/fixture/App.java"),
                "package fixture;\n" +
                        "public class App {\n" +
                        "    public static void main(String[] args) {\n" +
                        "        new stublib.Stub().danger();\n" +
                        "    }\n" +
                        "}\n")
        def second = runner("checkReachability", "--stacktrace").buildAndFail()
        println second.output

        then: "the changed app classes invalidate the task; the verdict flips to REACHABLE"
        second.task(":checkReachability").outcome == TaskOutcome.FAILED
        second.output.contains("VULN-POS")
        second.output.contains("REACHABLE")
        second.output.contains("fixture.App#main -> stublib.Stub#danger")
    }

    def "given a project whose osv directory starts empty when a record is added then the task re-runs and fails"() {
        given:
        writeSafeFixture(new File(BOM_MINI).absolutePath, "osv-empty", false)

        when:
        def first = runner("checkReachability").build()
        println first.output

        then:
        first.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        first.output.contains("No vulnerability candidates")

        when: "the snapshot gains a record"
        Files.copy(Path.of(new File(OSV_MINI).absolutePath, "VULN-POS.json"),
                projectDir.resolve("osv-empty/VULN-POS.json"))
        def second = runner("checkReachability", "--stacktrace").build()
        println second.output

        then: "the changed osv content invalidates the task; the candidate is now analyzed"
        second.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        second.output.contains("VULN-POS")
        second.output.contains("UNREACHABLE")
    }

    def "given a project with a local sbom copy when the sbom pins the fixed version then the task re-runs and passes"() {
        given:
        Files.copy(Path.of(new File(BOM_MINI).absolutePath), projectDir.resolve("bom.json"))
        writeSafeFixture("bom.json", "osv-mini", true)

        when:
        def first = runner("checkReachability").build()
        println first.output

        then:
        first.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        Files.exists(projectDir.resolve("build/reachability-report.json"))

        when: "the sbom no longer lists the affected version"
        Path bom = projectDir.resolve("bom.json")
        Files.writeString(bom, Files.readString(bom).replace('"1.0"', '"2.0"').replace("@1.0", "@2.0"))
        def second = runner("checkReachability").build()
        println second.output

        then: "the changed sbom content invalidates the task; no candidates remain"
        second.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        second.output.contains("No vulnerability candidates")
    }

    def "given a built project when the same content is built from a new directory with the build cache then the task is restored from the cache"() {
        given:
        Files.copy(Path.of(new File(BOM_MINI).absolutePath), projectDir.resolve("bom.json"))
        writeSafeFixture("bom.json", "osv-mini", true)
        Path copy = projectDir.parent.resolve(projectDir.fileName.toString() + "-copy")

        when:
        def first = runner("checkReachability", "--build-cache").build()
        println first.output

        then: "a fresh project has no local history: the task runs or is a cache hit"
        first.task(":checkReachability").outcome in [TaskOutcome.SUCCESS, TaskOutcome.FROM_CACHE]
        Files.exists(projectDir.resolve("build/reachability-report.json"))

        when:
        copyProjectTo(copy)
        def second = runnerIn(copy, "checkReachability", "--build-cache").build()
        println second.output

        then: "content-only inputs make the task cacheable; the outputs are restored"
        second.task(":checkReachability").outcome == TaskOutcome.FROM_CACHE
        Files.exists(copy.resolve("build/reachability-cp.txt"))
        Files.exists(copy.resolve("build/reachability-report.json"))
    }

    // --- M9: out-of-process execution --------------------------------------
    // The analysis runs in a forked worker process; the worker announces its
    // own pid (the daemon's lines would never print it), so the line's
    // presence is the isolation pin.

    def "given a project when checkReachability runs then the analysis executes in a forked worker process"() {
        given:
        writeSafeFixture(new File(BOM_MINI).absolutePath, "osv-mini", true)

        when:
        def result = runner("checkReachability").build()
        println result.output

        then:
        result.task(":checkReachability").outcome == TaskOutcome.SUCCESS
        result.output.contains("reachability: analysis runs in process ")
    }

    def "given a vulnerable project when checkReachability fails then the failure names the report files"() {
        given:
        writeFixtureProject(new File(OSV_MINI).absolutePath, false)

        when:
        def result = runner("checkReachability", "--stacktrace").buildAndFail()
        println result.output

        then: "the worker's exception is unwrapped to the task's own message"
        result.output.contains("reachable vulnerabilities found - see")
        result.output.contains("reachability-report.json")
    }
}
