package org.crazyrock.callis.analysis

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T31/T34 context tests (M3): app class directory + classpath file → resolved
 * jars, warnings for unreadable entries, and the app class name set.
 */
class AnalysisContextSpec extends Specification {

    private static final File MINI_APP = new File("src/test/resources/fixtures/mini-app")
    private static final File STUB_JAR = new File(MINI_APP, "stublib.jar")

    @TempDir
    Path workDir

    def "given the mini-app classes and no classpath file when built then jars and warnings are empty"() {
        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), null)

        then:
        context.jars().isEmpty()
        context.warnings().isEmpty()
        context.maxBytecodeMajor() == 69
    }

    def "given a classpath file with two jars on one line when built then both jars resolve"() {
        given:
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, "${STUB_JAR.absolutePath}:${STUB_JAR.absolutePath}".bytes)

        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        then: "duplicates are kept as listed (one warning-free jar entry per occurrence)"
        context.jars().collect { it.toString() } == [STUB_JAR.absolutePath, STUB_JAR.absolutePath]
        context.warnings().isEmpty()
    }

    def "given a classpath file with newline separated jars when built then all resolve"() {
        given:
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, "${STUB_JAR.absolutePath}\n${STUB_JAR.absolutePath}".bytes)

        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        then:
        context.jars().size() == 2
    }

    def "given a classpath file listing a missing jar when built then a warning is collected and the jar skipped"() {
        given:
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, "${STUB_JAR.absolutePath}:${workDir.resolve('missing.jar')}".bytes)

        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        then:
        context.jars().collect { it.toString() } == [STUB_JAR.absolutePath]
        context.warnings().any { it.contains("missing.jar") && it.contains("unreadable") }
    }

    def "given a classpath file that does not exist when built then a warning is collected"() {
        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(),
                workDir.resolve("no-such-cp.txt"))

        then:
        context.jars().isEmpty()
        context.warnings().any { it.contains("no-such-cp.txt") }
    }

    def "given an app class directory that does not exist when built then IOException"() {
        when:
        AnalysisContext.of(workDir.resolve("no-such-dir"), null)

        then:
        def e = thrown(IOException)
        e.message.contains("no-such-dir")
    }

    def "given the mini-app context when the classpath string is built then app dir and jar are joined"() {
        given:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), null)
        def jar = workDir.resolve("extra.jar")
        Files.write(jar, "x".bytes)

        when:
        String classpath = AnalysisContext
                .of(new File(MINI_APP, "classes").toPath(), classpathFileWith(jar))
                .classpathString()

        then:
        classpath == new File(MINI_APP, "classes").path + File.pathSeparator + jar.toString()

        and:
        context.classpathString() == new File(MINI_APP, "classes").path
    }

    private static Path classpathFileWith(Path jar) {
        def file = new File("build", "cp-context-spec.txt")
        file.parentFile.mkdirs()
        Files.write(file.toPath(), jar.toString().bytes)
        file.toPath()
    }

    def "given the mini-app classes when the app class names are read then all 54 binary names appear"() {
        when:
        Set<String> names = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), null).appClassNames()

        then:
        names.containsAll(["demo.Main", "demo.MainDanger", "demo.QuartzJobImpl",
                           "demo.WebController", "demo.MyJob", "demo.NotAMain", "demo.DeadCall",
                           "demo.VulnCaller", "demo.VulnCaller2", "demo.VulnService",
                           "demo.PointerDemo", "demo.PointerDemo2", "demo.PIface", "demo.SafeImpl", "demo.DangerImpl",
                           "demo.chain.C01", "demo.chain.ChainEnd", "demo.chain.DiamondEnd"])
        names.size() == 54
    }

    def "given a classpath file with blank lines when built then the empty entries are skipped"() {
        given: "an empty line yields an empty entry after the colon split"
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, "${STUB_JAR.absolutePath}\n\n${STUB_JAR.absolutePath}".bytes)

        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        then:
        context.jars().collect { it.toString() } == [STUB_JAR.absolutePath, STUB_JAR.absolutePath]
        context.warnings().isEmpty()
    }

    def "given a classpath file listing a jar without read permission when built then a warning is collected"() {
        given:
        def jar = workDir.resolve("locked.jar")
        Files.write(jar, "jar".bytes)
        TestPermissions.withoutRead(jar)
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, jar.toString().bytes)

        when:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        then:
        context.jars().isEmpty()
        context.warnings().any { it.contains("locked.jar") && it.contains("unreadable") }

        cleanup:
        TestPermissions.ownerReadWriteExecute(jar)
    }

    def "given the bytecode v70 probe as app classes when built then the scan reports major 70"() {
        given:
        def dir = new File("src/test/resources/fixtures/bytecode/v70")

        when:
        def context = AnalysisContext.of(dir.toPath(), null)

        then:
        context.maxBytecodeMajor() == 70
        context.scan().aboveCeiling().size() == 1
    }
}
