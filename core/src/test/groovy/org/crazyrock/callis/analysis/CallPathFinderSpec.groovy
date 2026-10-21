package org.crazyrock.callis.analysis

import org.crazyrock.callis.engine.CallGraphPolicy

import sootup.callgraph.CallGraph
import sootup.core.signatures.MethodSignature
import sootup.core.signatures.PackageName
import sootup.java.core.types.JavaClassType
import sootup.java.core.views.JavaView
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T43 path extraction tests (M4): multi-source BFS over the RTA graph —
 * the plan's positive chain (main -> service -> danger), lexicographic
 * source tie-breaking with determinism, shortest-path preference, and
 * the empty-result branches (unreachable target, target pruned from the
 * graph, no sources).
 */
class CallPathFinderSpec extends Specification {

    private static final File MINI_APP = new File("src/test/resources/fixtures/mini-app")
    private static final File STUB_JAR = new File(MINI_APP, "stublib.jar")

    @TempDir
    Path workDir

    private JavaView view
    private Set<String> appClassNames

    def setup() {
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, STUB_JAR.absolutePath.bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)
        view = SootUpSetup.buildView(context, null)
        appClassNames = context.appClassNames()
    }

    private MethodSignature sig(String className, String methodName) {
        int dot = className.lastIndexOf('.')
        def type = dot < 0
                ? new JavaClassType(className, new PackageName(""))
                : new JavaClassType(className.substring(dot + 1), new PackageName(className.substring(0, dot)))
        // SootUp 3.0.1 getMethodsByName returns a Set of SootMethod; sort for a deterministic pick
        view.getClass(type).get().getMethodsByName(methodName).sort { it.toString() }.first().getSignature()
    }

    private List<MethodSignature> entries(List<String> overrides) {
        new EntryPointDetector().detect(view, appClassNames, overrides, [:])
    }

    private CallGraph graph(List<String> overrides) {
        CallGraphFactory.build(view, entries(overrides), CallGraphPolicy.RTA).graph()
    }

    def "given the positive chain when a path is found then the three hops appear in call order"() {
        given: "VulnCaller.main -> VulnService.work -> stublib.Stub.danger"
        CallGraph graph = graph(["demo.VulnCaller#main"])

        when:
        List<String> path = CallPathFinder.findPath(graph, entries(["demo.VulnCaller#main"]), sig("stublib.Stub", "danger"))

        then:
        path == ["demo.VulnCaller#main", "demo.VulnService#work", "stublib.Stub#danger"]
    }

    def "given two entry points at the same distance when a path is found then exactly one lexicographic-first path"() {
        given: "VulnCaller and VulnCaller2 both reach the same danger() call"
        CallGraph cg = graph(["demo.VulnCaller#main", "demo.VulnCaller2#main"])

        when:
        List<String> path = CallPathFinder.findPath(cg,
                entries(["demo.VulnCaller#main", "demo.VulnCaller2#main"]), sig("stublib.Stub", "danger"))

        then: "one path, led by the lexicographic first source"
        path == ["demo.VulnCaller#main", "demo.VulnService#work", "stublib.Stub#danger"]

        and: "a fresh graph and fresh entry list return the identical path (determinism)"
        CallGraph cgAgain = graph(["demo.VulnCaller2#main", "demo.VulnCaller#main"])
        CallPathFinder.findPath(cgAgain,
                entries(["demo.VulnCaller2#main", "demo.VulnCaller#main"]), sig("stublib.Stub", "danger")) == path
    }

    def "given a closer and a farther source when a path is found then the shortest path wins"() {
        given: "MainDanger calls danger() directly; VulnCaller goes through the service"
        CallGraph graph = graph(["demo.MainDanger#main", "demo.VulnCaller#main"])

        when:
        List<String> path = CallPathFinder.findPath(graph,
                entries(["demo.MainDanger#main", "demo.VulnCaller#main"]), sig("stublib.Stub", "danger"))

        then:
        path == ["demo.MainDanger#main", "stublib.Stub#danger"]
    }

    def "given a target never called from the entries when a path is found then the result is empty"() {
        given: "Main calls only safe(); RTA prunes danger() from the graph"
        CallGraph graph = graph(["demo.Main#main"])

        when:
        List<String> path = CallPathFinder.findPath(graph, entries(["demo.Main#main"]), sig("stublib.Stub", "danger"))

        then:
        path.isEmpty()

        and: "safe() is in the same graph and still yields its two-hop path"
        CallPathFinder.findPath(graph, entries(["demo.Main#main"]), sig("stublib.Stub", "safe")) ==
                ["demo.Main#main", "stublib.Stub#safe"]
    }

    def "given the target as its own source when a path is found then a single hop is returned"() {
        given:
        CallGraph graph = graph(["demo.Main#main"])

        when:
        List<String> path = CallPathFinder.findPath(graph, entries(["demo.Main#main"]), sig("demo.Main", "main"))

        then:
        path == ["demo.Main#main"]
    }

    def "given no entry points when a path is found then the result is empty"() {
        given:
        CallGraph graph = graph(["demo.Main#main"])

        expect:
        CallPathFinder.findPath(graph, [], sig("stublib.Stub", "danger")).isEmpty()
    }

    def "given a target that exists in the view but is pruned from the graph when a path is found then the result is empty"() {
        given: "BusinessService is never instantiated, so RTA keeps BusinessService#run out of the graph"
        CallGraph graph = graph(["demo.DeadCall#main", "demo.Main#main"])

        expect:
        CallPathFinder.findPath(graph, entries(["demo.DeadCall#main", "demo.Main#main"]),
                sig("demo.BusinessService", "run")).isEmpty()
    }

    def "given a null target when a path is found then the result is empty"() {
        given:
        CallGraph cg = graph(["demo.Main#main"])

        expect:
        CallPathFinder.findPath(cg, entries(["demo.Main#main"]), null).isEmpty()
    }

    def "given sources that are not in the graph when a path is found then the result is empty"() {
        given: "BusinessService#run exists in the view but is pruned from the RTA graph"
        CallGraph cg = graph(["demo.DeadCall#main", "demo.Main#main"])

        expect:
        CallPathFinder.findPath(cg, [sig("demo.BusinessService", "run")], sig("stublib.Stub", "danger")).isEmpty()
    }
}
