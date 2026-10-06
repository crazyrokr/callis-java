package org.reachability.analyzer.analysis

import sootup.core.signatures.MethodSignature
import sootup.java.core.views.JavaView
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T33 call graph tests (M3): RTA prunes dead code (the plan's false-positive
 * pin), CHA keeps it (the documented difference), and a callback entry point
 * reaches the dangerous call.
 */
class CallGraphFactorySpec extends Specification {

    private static final File MINI_APP = new File("src/test/resources/fixtures/mini-app")
    private static final File STUB_JAR = new File(MINI_APP, "stublib.jar")

    @TempDir
    Path workDir

    private JavaView view() {
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, STUB_JAR.absolutePath.bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)
        SootUpSetup.buildView(context, null)
    }

    private MethodSignature sig(JavaView view, String className, String methodName) {
        def cls = view.classes.collect().find { it.name == className }
        cls.getMethodsByName(methodName).first().getSignature()
    }

    private MethodSignature mainOf(JavaView view, String className) {
        sig(view, className, "main")
    }

    def "given the safe-only app when RTA is built then the graph contains safe() and prunes danger()"() {
        given: "demo.Main calls only stublib.Stub.safe()"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.Main")], false)

        then: "the plan's false-positive pin: dead dangerous code is not reachable"
        result.graph.containsMethod(sig(view, "demo.Main", "main"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "safe"))
        !result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the dangerous app when RTA is built then the graph contains danger()"() {
        given: "demo.MainDanger calls stublib.Stub.danger()"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.MainDanger")], false)

        then:
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the quartz callback entry when RTA is built then the call through it reaches danger()"() {
        given: "QuartzJobImpl.execute calls the dangerous method (A13 callback entry point)"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [sig(view, "demo.QuartzJobImpl", "execute")], false)

        then:
        result.graph.containsMethod(sig(view, "demo.QuartzJobImpl", "execute"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the dead virtual call when RTA is built then the never-instantiated implementation is pruned"() {
        given: "demo.DeadCall calls Business.run() on a null reference; BusinessService is never instantiated"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.DeadCall")], false)

        then: "RTA prunes BusinessService.run and the danger() call inside it"
        !result.graph.containsMethod(sig(view, "demo.BusinessService", "run"))
        !result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the dead virtual call when CHA is built then the implementation stays in the graph"() {
        given: "CHA resolves the virtual call to every implementation (the documented precision difference)"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.DeadCall")], true)

        then:
        result.graph.containsMethod(sig(view, "demo.BusinessService", "run"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the same fixture when built with CHA and RTA then CHA keeps at least everything RTA reaches"() {
        given:
        def view = view()
        def entry = mainOf(view, "demo.Main")

        when:
        def rta = CallGraphFactory.build(view, [entry], false)
        def cha = CallGraphFactory.build(view, [entry], true)

        then: "CHA is a superset for this fixture (no instantiation-sensitive pruning)"
        rta.graph.getMethodSignatures().every { cha.graph.containsMethod(it) }
    }

    def "given empty entry points when the graph is built then the graph is empty"() {
        given:
        def view = view()

        when:
        def rta = CallGraphFactory.build(view, [], false)
        def cha = CallGraphFactory.build(view, [], true)

        then:
        rta.nodeCount == 0 && rta.edgeCount == 0
        cha.nodeCount == 0 && cha.edgeCount == 0
    }

    def "given a built graph when inspected then size and time are reported"() {
        given:
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.Main")], false)

        then:
        result.nodeCount >= 2
        result.edgeCount >= 1
        result.buildMillis >= 0
    }
}
