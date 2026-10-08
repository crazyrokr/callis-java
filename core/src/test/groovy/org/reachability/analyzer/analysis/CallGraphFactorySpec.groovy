package org.reachability.analyzer.analysis

import org.reachability.analyzer.engine.CallGraphPolicy
import sootup.core.signatures.MethodSignature
import sootup.java.core.views.JavaView
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T33 call graph tests (M3): RTA prunes dead code (the plan's false-positive
 * pin), CHA keeps it (the documented difference), and a callback entry point
 * reaches the dangerous call. M7b (A5): the SPARK object-sensitive mode —
 * the PointerDemo/PointerDemo2 fixtures pin the whole precision hierarchy:
 * CHA and RTA keep the instantiated-but-never-dispatched implementation (the
 * RTA false positive, because SootUp 3.0.1's RTA tracks instantiation per
 * program rather than per receiver), while SPARK prunes it (the true
 * negative) and still keeps every genuinely reachable call.
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
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.Main")], CallGraphPolicy.RTA)

        then: "the plan's false-positive pin: dead dangerous code is not reachable"
        result.graph.containsMethod(sig(view, "demo.Main", "main"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "safe"))
        !result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the dangerous app when RTA is built then the graph contains danger()"() {
        given: "demo.MainDanger calls stublib.Stub.danger()"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.MainDanger")], CallGraphPolicy.RTA)

        then:
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the quartz callback entry when RTA is built then the call through it reaches danger()"() {
        given: "QuartzJobImpl.execute calls the dangerous method (A13 callback entry point)"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [sig(view, "demo.QuartzJobImpl", "execute")], CallGraphPolicy.RTA)

        then:
        result.graph.containsMethod(sig(view, "demo.QuartzJobImpl", "execute"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the dead virtual call when RTA is built then the never-instantiated implementation is pruned"() {
        given: "demo.DeadCall calls Business.run() on a null reference; BusinessService is never instantiated"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.DeadCall")], CallGraphPolicy.RTA)

        then: "RTA prunes BusinessService.run and the danger() call inside it"
        !result.graph.containsMethod(sig(view, "demo.BusinessService", "run"))
        !result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the dead virtual call when CHA is built then the implementation stays in the graph"() {
        given: "CHA resolves the virtual call to every implementation (the documented precision difference)"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.DeadCall")], CallGraphPolicy.CHA)

        then:
        result.graph.containsMethod(sig(view, "demo.BusinessService", "run"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the same fixture when built with CHA and RTA then CHA keeps at least everything RTA reaches"() {
        given:
        def view = view()
        def entry = mainOf(view, "demo.Main")

        when:
        def rta = CallGraphFactory.build(view, [entry], CallGraphPolicy.RTA)
        def cha = CallGraphFactory.build(view, [entry], CallGraphPolicy.CHA)

        then: "CHA is a superset for this fixture (no instantiation-sensitive pruning)"
        rta.graph.getMethodSignatures().every { cha.graph.containsMethod(it) }
    }

    def "given empty entry points when the graph is built then the graph is empty"() {
        given:
        def view = view()

        when:
        def rta = CallGraphFactory.build(view, [], CallGraphPolicy.RTA)
        def cha = CallGraphFactory.build(view, [], CallGraphPolicy.CHA)
        def spark = CallGraphFactory.build(view, [], CallGraphPolicy.SPARK)

        then:
        rta.nodeCount == 0 && rta.edgeCount == 0
        cha.nodeCount == 0 && cha.edgeCount == 0
        spark.nodeCount == 0 && spark.edgeCount == 0
    }

    def "given a built graph when inspected then size and time are reported"() {
        given:
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.Main")], CallGraphPolicy.RTA)

        then:
        result.nodeCount >= 2
        result.edgeCount >= 1
        result.buildMillis >= 0
    }

    // ------------------------------------------------------------------
    // M7b (A5): the SPARK object-sensitive mode on the PointerDemo fixtures.
    // ------------------------------------------------------------------

    def "given the allocation-only pointer demo when RTA is built then the never-instantiated implementation is already pruned"() {
        given: "PointerDemo constructs only SafeImpl; SootUp 3.0.1's RTA tracks instantiation, so the false positive of classic RTA does not appear here"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.PointerDemo")], CallGraphPolicy.RTA)

        then: "the safe call is in the graph; the dangerous one is not"
        result.graph.containsMethod(sig(view, "demo.SafeImpl", "op"))
        !result.graph.containsMethod(sig(view, "demo.DangerImpl", "op"))
        !result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the instantiated-but-undispatched implementation when RTA is built then the false-positive call is kept"() {
        given: "PointerDemo2 instantiates DangerImpl (by assignment) but never dispatches to it at the op() site"
        def view = view()

        when: "RTA resolves the virtual call to every instantiated subtype - the documented RTA false positive"
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.PointerDemo2")], CallGraphPolicy.RTA)

        then:
        result.graph.containsMethod(sig(view, "demo.DangerImpl", "op"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the instantiated-but-undispatched implementation when CHA is built then the false-positive call is kept"() {
        given: "CHA is even less precise: every implementation of PIface is a call target"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.PointerDemo2")], CallGraphPolicy.CHA)

        then:
        result.graph.containsMethod(sig(view, "demo.DangerImpl", "op"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the instantiated-but-undispatched implementation when SPARK is built then the call is pruned (the true negative)"() {
        given: "PointerDemo2 instantiates DangerImpl but the receiver of op() only ever points at SafeImpl"
        def view = view()
        def dangerSig = sig(view, "stublib.Stub", "danger")

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.PointerDemo2")], CallGraphPolicy.SPARK)

        then: "no points-to fact dispatches to DangerImpl.op(), so the dangerous call is out of the graph"
        !result.graph.containsMethod(sig(view, "demo.DangerImpl", "op"))
        !result.graph.containsMethod(dangerSig)

        and: "what really runs stays in: the constructor that IS called, the safe dispatch, the safe call"
        result.graph.getMethodSignatures().any {
            it.getDeclClassType().getFullyQualifiedName() == "demo.DangerImpl" && it.getName() == "<init>"
        }
        result.graph.containsMethod(sig(view, "demo.SafeImpl", "op"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "safe"))
        result.nodeCount > 0 && result.edgeCount > 0 && result.buildMillis >= 0
    }

    def "given the positive chain when SPARK is built then the reachable call stays in the graph"() {
        given: "VulnCaller -> VulnService.work -> Stub.danger: concrete allocations at every hop"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.VulnCaller")], CallGraphPolicy.SPARK)

        then: "the true positive survives the pointer analysis"
        result.graph.containsMethod(sig(view, "demo.VulnService", "work"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
    }

    def "given the pointer demos with two entries when SPARK is built then each entry refines independently"() {
        given: "PointerDemo (allocation-only) and VulnCaller (the positive chain) as separate entries"
        def view = view()

        when:
        def result = CallGraphFactory.build(view, [mainOf(view, "demo.PointerDemo"), mainOf(view, "demo.VulnCaller")],
                CallGraphPolicy.SPARK)

        then: "the safe dispatch and the positive chain coexist; nothing dangerous is added"
        result.graph.containsMethod(sig(view, "demo.SafeImpl", "op"))
        result.graph.containsMethod(sig(view, "demo.VulnService", "work"))
        result.graph.containsMethod(sig(view, "stublib.Stub", "danger"))
        !result.graph.getMethodSignatures().any {
            it.getDeclClassType().getFullyQualifiedName() == "demo.DangerImpl"
        }
    }

    def "given the same fixture when SPARK and RTA are built then SPARK is a subset of RTA"() {
        given: "the RTA false-positive fixture: RTA is sound-but-coarse, SPARK refines it"
        def view = view()
        def entry = mainOf(view, "demo.PointerDemo2")

        when:
        def rta = CallGraphFactory.build(view, [entry], CallGraphPolicy.RTA)
        def spark = CallGraphFactory.build(view, [entry], CallGraphPolicy.SPARK)

        then: "every SPARK node and edge pair is in the RTA graph"
        spark.graph.getMethodSignatures().every { rta.graph.containsMethod(it) }
        def rtaPairs = rta.graph.getCalls().collect { [it.sourceMethodSignature(), it.targetMethodSignature()] }
        spark.graph.getCalls().collect { [it.sourceMethodSignature(), it.targetMethodSignature()] }.every {
            it in rtaPairs
        }

        and: "SPARK prunes at least one RTA node"
        spark.nodeCount < rta.nodeCount
    }
}
