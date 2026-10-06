package org.reachability.analyzer.analysis

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T31/T34 setup tests (M3): one JavaView over app classes + jars, the A12
 * guard before the view, and the zero-classes fail-loud check.
 */
class SootUpSetupSpec extends Specification {

    private static final File MINI_APP = new File("src/test/resources/fixtures/mini-app")
    private static final File STUB_JAR = new File(MINI_APP, "stublib.jar")

    @TempDir
    Path workDir

    def "given the mini-app with the stub jar when the view is built then app and library classes are visible"() {
        given:
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, STUB_JAR.absolutePath.bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        when:
        def view = SootUpSetup.buildView(context, null)
        def names = view.classes.collect { it.name }

        then:
        names.containsAll(["demo.Main", "demo.QuartzJobImpl", "stublib.Stub", "libpkg.Tool"])
        !names.contains("demo.Main\$1")
    }

    def "given app classes without any jar when the view is built then the app classes are visible"() {
        given:
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), null)

        when:
        def view = SootUpSetup.buildView(context, null)
        def names = view.classes.collect { it.name }

        then:
        names.contains("demo.Main")
        !names.contains("stublib.Stub")
    }

    def "given classes at the java 25 ceiling when the view is built then no guard error"() {
        given:
        def context = AnalysisContext.of(new File("src/test/resources/fixtures/bytecode/v69").toPath(), null)

        when:
        SootUpSetup.buildView(context, null)

        then:
        notThrown(AnalysisException)
    }

    def "given classes above the ceiling when the view is built then AnalysisException before any parsing"() {
        given:
        def context = AnalysisContext.of(new File("src/test/resources/fixtures/bytecode/v70").toPath(), null)

        when:
        SootUpSetup.buildView(context, null)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("ceiling")
        e.message.contains("69")
    }

    def "given a non-empty directory with only corrupt class files when the view is built then fail loudly"() {
        given: "a .class file whose header SootUp cannot parse (magic is garbage, major decodes to 0)"
        Files.write(workDir.resolve("Corrupt.class"), ([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] as byte[]))
        def context = AnalysisContext.of(workDir, null)

        when:
        SootUpSetup.buildView(context, null)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("zero classes")
        e.message.contains("1 class file(s)")
    }

    def "given a corrupt file with a valid version 69 header when the view is built then fail loudly naming the major"() {
        given: "magic + minor 0 + major 69, then garbage: SootUp parses nothing, the guard reports the major"
        Files.write(workDir.resolve("HalfBaked.class"),
                ([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x45] + ([0x77] * 16)) as byte[])
        def context = AnalysisContext.of(workDir, null)

        when:
        SootUpSetup.buildView(context, null)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("zero classes")
        e.message.contains("max class file major 69")
    }

    def "given an empty app class directory when the view is built then no zero-classes error"() {
        given: "no class files at all: the guard's class-file precondition is false"
        Files.write(workDir.resolve("notes.txt"), "no classes here".bytes)
        def context = AnalysisContext.of(workDir, null)

        when:
        SootUpSetup.buildView(context, null)

        then:
        notThrown(AnalysisException)
    }

    def "given a classpath file with a missing jar when the view is built then the warning is on the context"() {
        given:
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, "${workDir.resolve('missing.jar')}".bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)

        when:
        def view = SootUpSetup.buildView(context, null)

        then:
        context.warnings().any { it.contains("missing.jar") }
        view.classes.collect { it.name }.contains("demo.Main")
    }

    def "given an out of memory hint when formatted then the message carries the -Xmx guidance"() {
        expect:
        SootUpSetup.memoryHint(null).contains("-Xmx4g")
        SootUpSetup.memoryHint("Java heap space").contains("Java heap space")
    }
}
