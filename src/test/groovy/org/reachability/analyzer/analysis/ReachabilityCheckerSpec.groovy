package org.reachability.analyzer.analysis

import sootup.callgraph.CallGraph
import sootup.core.signatures.MethodSignature
import sootup.java.core.views.JavaView
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

import org.reachability.analyzer.osv.VulnerabilityCandidate

/**
 * T41 verdict model tests (M4): METHOD-level and ARTIFACT-level matching,
 * the REACHABLE / UNREACHABLE / NO_CLASS_INFO states, the A14 onClasspath
 * flag (the flagship false-positive: artifact present, nothing reachable),
 * deterministic path selection, and unknown-mapping-id warnings.
 */
class ReachabilityCheckerSpec extends Specification {

    private static final File MINI_APP = new File("src/test/resources/fixtures/mini-app")
    private static final File STUB_JAR = new File(MINI_APP, "stublib.jar")
    private static final File VALID_MAPPINGS = new File("src/test/resources/fixtures/mappings/valid.json")

    @TempDir
    Path workDir

    private JavaView view
    private Set<String> appClassNames
    private Map<String, List<VulnMappingLoader.VulnTarget>> mappings
    private ArtifactClassIndex index

    def setup() {
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, STUB_JAR.absolutePath.bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)
        view = SootUpSetup.buildView(context, null)
        appClassNames = context.appClassNames()
        mappings = new VulnMappingLoader().load(VALID_MAPPINGS.toPath())
        index = new ArtifactClassIndex(context.jars())
    }

    private List<MethodSignature> entries(List<String> overrides) {
        new EntryPointDetector().detect(view, appClassNames, overrides, [:])
    }

    private CallGraph graph(List<String> overrides) {
        CallGraphFactory.build(view, entries(overrides), false).graph()
    }

    private static VulnerabilityCandidate candidate(String id, String component, String version) {
        new VulnerabilityCandidate(id, [], "Test vulnerability", component, version,
                "pkg:maven/" + component.replace(":", "/") + "@" + version, [], component, ["ranges: 0 -> 2.0"])
    }

    def "given a reachable mapped method when checked then the verdict is REACHABLE with the method-level path"() {
        given:
        def entries = entries(["demo.VulnCaller#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        List<ReachabilityChecker.Verdict> verdicts = checker.check(
                [candidate("VULN-POS", "stublib:stublib", "1.0")], ["VULN-POS": mappings["VULN-POS"]], index)

        then:
        verdicts.size() == 1
        def verdict = verdicts[0]
        verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.METHOD
        verdict.onClasspath()
        verdict.path() == ["demo.VulnCaller#main", "demo.VulnService#work", "stublib.Stub#danger"]
        checker.warnings().isEmpty()
    }

    def "given a mapped method never called from the entries when checked then UNREACHABLE with onClasspath (A14)"() {
        given: "Main calls only safe(); the artifact itself is present in the parsed view"
        def entries = entries(["demo.Main#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check(
                [candidate("VULN-POS", "stublib:stublib", "1.0")], ["VULN-POS": mappings["VULN-POS"]], index)[0]

        then: "the verdict is UNREACHABLE, not an error, and onClasspath is set for the NOTICE"
        verdict.status() == ReachabilityChecker.VerdictStatus.UNREACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.METHOD
        verdict.onClasspath()
        verdict.path().isEmpty()
    }

    def "given a mapped method present in the view but never called when checked then UNREACHABLE at method level"() {
        given: "safe() exists but only MainDanger#main is the entry, and it calls danger()"
        def entries = entries(["demo.MainDanger#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check(
                [candidate("VULN-NEG", "stublib:stublib", "1.0")], ["VULN-NEG": mappings["VULN-NEG"]], index)[0]

        then:
        verdict.status() == ReachabilityChecker.VerdictStatus.UNREACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.METHOD
        verdict.onClasspath()
        verdict.path().isEmpty()
    }

    def "given a mapped class absent from the view when checked then the artifact fallback yields NO_CLASS_INFO"() {
        given: "nope.Gone is in neither the view nor any jar"
        def entries = entries(["demo.Main#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check(
                [candidate("VULN-NOCLASS", "nope:Gone", "1.0")], mappings, index)[0]

        then:
        verdict.status() == ReachabilityChecker.VerdictStatus.NO_CLASS_INFO
        verdict.level() == ReachabilityChecker.MatchLevel.ARTIFACT
        !verdict.onClasspath()
        verdict.path().isEmpty()

        and: "the mapping ids that matched no candidate are warned"
        checker.warnings().any { it.contains("VULN-POS") }
        checker.warnings().any { it.contains("VULN-DESC") }
    }

    def "given a candidate without a mapping for an artifact absent from the classpath when checked then NO_CLASS_INFO"() {
        given: "log4j-core is in the SBOM but not on the classpath file"
        def entries = entries(["demo.Main#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check([candidate("VULN-LOG", "log4j:log4j-core", "2.14.1")], [:], index)[0]

        then:
        verdict.status() == ReachabilityChecker.VerdictStatus.NO_CLASS_INFO
        verdict.level() == ReachabilityChecker.MatchLevel.ARTIFACT
        !verdict.onClasspath()
        verdict.path().isEmpty()
    }

    def "given a candidate without a mapping and a reachable artifact method when checked then REACHABLE at artifact level"() {
        given: "three entries reach the artifact; MainDanger is the lexicographic first closest caller"
        def overrides = ["demo.Main#main", "demo.MainDanger#main", "demo.VulnCaller#main"]
        def entries = entries(overrides)
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check([candidate("VULN-POS", "stublib:stublib", "1.0")], [:], index)[0]

        then:
        verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.ARTIFACT
        verdict.onClasspath()
        verdict.path() == ["demo.MainDanger#main", "stublib.Stub#danger"]
    }

    def "given an artifact present in the view with no reachable methods when checked then UNREACHABLE with onClasspath"() {
        given: "a second jar carrying only jakarta servlet classes; nothing calls them from the entries"
        def jakartaJar = workDir.resolve("jakarta-servlet.jar")
        new java.util.zip.ZipFile(STUB_JAR).withCloseable { zsrc ->
            new java.util.zip.ZipOutputStream(java.nio.file.Files.newOutputStream(jakartaJar)).withCloseable { zout ->
                zsrc.entries().each { e ->
                    if (!e.isDirectory() && e.name.startsWith("jakarta/")) {
                        zout.putNextEntry(new java.util.zip.ZipEntry(e.name))
                        zsrc.getInputStream(e).withCloseable { in -> in.transferTo(zout) }
                        zout.closeEntry()
                    }
                }
            }
        }
        def cp = workDir.resolve("cp-2jars.txt")
        Files.write(cp, [STUB_JAR.absolutePath, jakartaJar.toString()].join(":").bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)
        def twoJarView = SootUpSetup.buildView(context, null)
        def twoJarIndex = new ArtifactClassIndex(context.jars())
        def entries = new EntryPointDetector().detect(twoJarView, context.appClassNames(), ["demo.Main#main"], [:])
        def checker = new ReachabilityChecker(twoJarView, CallGraphFactory.build(twoJarView, entries, false).graph(), entries)

        when:
        def verdict = checker.check([candidate("VULN-JAKARTA", "jakarta:jakarta-servlet", "5.0")], [:], twoJarIndex)[0]

        then: "artifact classes are in the view, but none of their methods is reachable"
        verdict.status() == ReachabilityChecker.VerdictStatus.UNREACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.ARTIFACT
        verdict.onClasspath()
        verdict.path().isEmpty()
    }

    def "given a mapped target with a descriptor when checked then the overload is resolved and the verdict REACHABLE"() {
        given:
        def entries = entries(["demo.VulnCaller#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check(
                [candidate("VULN-DESC", "stublib:stublib", "1.0")], ["VULN-DESC": mappings["VULN-DESC"]], index)[0]

        then:
        verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.METHOD
        verdict.path() == ["demo.VulnCaller#main", "demo.VulnService#work", "stublib.Stub#danger"]
    }

    def "given mapping ids without matching candidates when checked then each unknown id is warned"() {
        given:
        def entries = entries(["demo.Main#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when: "only VULN-POS is a candidate; the fixture mapping carries three more ids"
        checker.check([candidate("VULN-POS", "stublib:stublib", "1.0")], mappings, index)

        then:
        def warnings = checker.warnings()
        warnings.size() == 3
        warnings.every { it.contains("unknown") }
        warnings.any { it.contains("VULN-DESC") }
        warnings.any { it.contains("VULN-NEG") }
        warnings.any { it.contains("VULN-NOCLASS") }
    }

    def "given a mapping with an empty target list when checked then the artifact level is used"() {
        given:
        def entries = entries(["demo.VulnCaller#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check(
                [candidate("VULN-POS", "stublib:stublib", "1.0")], ["VULN-POS": []], index)[0]

        then: "no mapped methods: the artifact level finds the reachable danger() call"
        verdict.status() == ReachabilityChecker.VerdictStatus.REACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.ARTIFACT
        verdict.path() == ["demo.VulnCaller#main", "demo.VulnService#work", "stublib.Stub#danger"]
    }

    def "given a mapped descriptor that fits only one overload when checked then the matching overload is used"() {
        given: "BadMains has five main() overloads; the (int) descriptor fits exactly one"
        def entries = entries(["demo.Main#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)
        def targets = [new VulnMappingLoader.VulnTarget("demo.BadMains", "main", "(int)")]

        when:
        def verdict = checker.check([candidate("VULN-BAD", "demo:BadMains", "1.0")], ["VULN-BAD": targets], index)[0]

        then: "BadMains#main(int) is in the view but never called from the entries"
        verdict.status() == ReachabilityChecker.VerdictStatus.UNREACHABLE
        verdict.level() == ReachabilityChecker.MatchLevel.METHOD
        verdict.onClasspath()
        verdict.path().isEmpty()
    }

    def "given a mapped class in the default package when checked then the package-less name is parsed"() {
        given: "Gone carries no package prefix"
        def entries = entries(["demo.Main#main"])
        def checker = new ReachabilityChecker(view, CallGraphFactory.build(view, entries, false).graph(), entries)

        when:
        def verdict = checker.check(
                [candidate("VULN-GONE", "default:Gone", "1.0")],
                ["VULN-GONE": [new VulnMappingLoader.VulnTarget("Gone", "gone", null)]], index)[0]

        then: "Gone is in neither the view nor any jar"
        verdict.status() == ReachabilityChecker.VerdictStatus.NO_CLASS_INFO
        verdict.level() == ReachabilityChecker.MatchLevel.ARTIFACT
        !verdict.onClasspath()
    }

    def "given the same input checked twice when run on fresh graphs then the verdicts are identical"() {
        given:
        def overrides = ["demo.VulnCaller#main", "demo.VulnCaller2#main"]
        def firstEntries = entries(overrides)
        def first = new ReachabilityChecker(view, CallGraphFactory.build(view, firstEntries, false).graph(), firstEntries)
        def secondEntries = entries(overrides)
        def second = new ReachabilityChecker(view, CallGraphFactory.build(view, secondEntries, false).graph(), secondEntries)
        def candidates = [candidate("VULN-POS", "stublib:stublib", "1.0")]

        when:
        def a = first.check(candidates, ["VULN-POS": mappings["VULN-POS"]], index)[0]
        def b = second.check(candidates, ["VULN-POS": mappings["VULN-POS"]], index)[0]

        then:
        a.status() == b.status()
        a.path() == b.path()
        a.path()[0] == "demo.VulnCaller#main"
    }
}
