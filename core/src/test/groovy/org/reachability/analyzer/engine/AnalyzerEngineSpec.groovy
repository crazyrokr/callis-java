package org.reachability.analyzer.engine

import com.fasterxml.jackson.databind.ObjectMapper
import org.reachability.analyzer.analysis.TestPermissions
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * M7a: the AnalyzerEngine facade — the in-process contract that the CLI and
 * the Gradle/Maven plugins share. Mirrors the CliSpec pipeline scenarios at
 * the facade level: exit codes (A8), the console lines via the sink, the
 * report content on disk, and the stale-report deletion contract.
 */
class AnalyzerEngineSpec extends Specification {

    private static final String BOM_MINI = "src/test/resources/fixtures/bom-mini.json"
    private static final String OSV_MINI = "src/test/resources/fixtures/osv-mini"
    private static final String MAPPINGS = "src/test/resources/fixtures/mappings/valid.json"
    private static final String MINI_APP_CLASSES = "src/test/resources/fixtures/mini-app/classes"

    @TempDir
    Path work

    private final ObjectMapper mapper = new ObjectMapper()

    private Path miniAppCpFile() {
        def cp = work.resolve("cp.txt")
        Files.writeString(cp, new File("src/test/resources/fixtures/mini-app/stublib.jar").absolutePath + "\n")
        cp
    }

    private static class CapturingSink implements DiagnosticSink {
        final List<String> outLines = []
        final List<String> errLines = []

        @Override
        void out(String line) {
            outLines << line
        }

        @Override
        void err(String line) {
            errLines << line
        }

        String out() {
            outLines.join("\n")
        }

        String err() {
            errLines.join("\n")
        }
    }

    private AnalysisRequest request() {
        new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(Path.of(MAPPINGS)),
                CallGraphPolicy.RTA,
                List.of(),
                Map.of(),
                Optional.empty())
    }

    def "given a reachable vulnerability when analyzed then exit one with a CRITICAL line and the reachable report entry"() {
        given:
        def sink = new CapturingSink()

        when:
        def result = AnalyzerEngine.analyze(request(), work.resolve("reachability-report"),
                [ReportFormat.JSON, ReportFormat.JUNITXML], false, sink)

        then: "the mapped method is called from the app: REACHABLE, exit 1"
        result.exitCode() == 1
        sink.out().contains("CRITICAL: VULN-POS")
        sink.out().contains("REACHABLE")
        sink.out().contains("demo.MainDanger#main -> stublib.Stub#danger")
        sink.out().contains("1 candidate(s): 1 reachable")

        and: "both reports exist; the JSON entry is REACHABLE with the path"
        Files.exists(work.resolve("reachability-report.json"))
        Files.exists(work.resolve("reachability-report.junit.xml"))
        def json = mapper.readTree(work.resolve("reachability-report.json").toFile())
        def entry = json.get("vulnerabilities").get(0)
        entry.get("verdict").asText() == "REACHABLE"
        entry.get("path").size() > 0
    }

    def "given the vulnerable call excluded from the entry points when analyzed then exit zero with an on-classpath NOTICE"() {
        given:
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(Path.of(MAPPINGS)),
                CallGraphPolicy.RTA,
                ["demo.Main#main"] as List,
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then: "UNREACHABLE with the A14 onClasspath notice, exit 0"
        result.exitCode() == 0
        sink.out().contains("NOTICE: VULN-POS")
        sink.out().contains("UNREACHABLE")
        sink.out().contains("artifact present in classpath")
        sink.out().contains("1 candidate(s): 0 reachable")
        def json = mapper.readTree(work.resolve("reachability-report.json").toFile())
        json.get("vulnerabilities").get(0).get("verdict").asText() == "UNREACHABLE"
        json.get("vulnerabilities").get(0).get("onClasspath").asBoolean()
    }

    def "given a zero-candidate pipeline and a previous run's reports when analyzed then the stale reports are removed"() {
        given: "an empty OSV directory (no candidates) and stale report files"
        def emptyDir = work.resolve("osv-empty")
        Files.createDirectories(emptyDir)
        def staleJson = work.resolve("stale.json")
        def staleXml = work.resolve("stale.junit.xml")
        Files.writeString(staleJson, '{"stale": true}')
        Files.writeString(staleXml, "<testsuite/>")
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                emptyDir,
                Optional.empty(),
                Optional.empty(),
                CallGraphPolicy.RTA,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("stale"),
                [ReportFormat.JSON, ReportFormat.JUNITXML], false, sink)

        then: "the early exit must not leave a previous run's report behind"
        result.exitCode() == 0
        sink.out().contains("No vulnerability candidates")
        !Files.exists(staleJson)
        !Files.exists(staleXml)
    }

    def "given a checksum mismatch when analyzed then exit two with the mismatch line"() {
        given:
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.of("0000000000000000000000000000000000000000000000000000000000000000"),
                Optional.empty(),
                CallGraphPolicy.RTA,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then: "the pin refuses a changed snapshot (A14)"
        result.exitCode() == 2
        sink.err().contains("OSV snapshot checksum mismatch")
    }

    def "given a malformed mappings file when analyzed then exit two with the loader error"() {
        given:
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(Path.of("src/test/resources/fixtures/mappings/malformed.json")),
                CallGraphPolicy.RTA,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then:
        result.exitCode() == 2
        sink.err().contains("malformed.json")
        sink.err().contains("object")
    }

    def "given a missing mappings file when analyzed then exit two with the read error"() {
        given:
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(work.resolve("no-such-mappings.json")),
                CallGraphPolicy.RTA,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then:
        result.exitCode() == 2
        sink.err().contains("cannot read mappings")
    }

    def "given the CHA policy when analyzed then the same verdicts hold and the report names the CHA builder"() {
        given:
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(Path.of(MAPPINGS)),
                CallGraphPolicy.CHA,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then: "CHA is less precise but the same mapped call is still reachable"
        result.exitCode() == 1
        sink.out().contains("CRITICAL: VULN-POS")
        def json = mapper.readTree(work.resolve("reachability-report.json").toFile())
        json.get("metadata").get("callGraphBuilder").asText() == "CHA"
    }

    def "given the SPARK policy when analyzed then the same verdicts hold and the report names the SPARK builder"() {
        given:
        def sink = new CapturingSink()
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(Path.of(MAPPINGS)),
                CallGraphPolicy.SPARK,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, work.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then: "SPARK is the most precise mode but the same mapped call is still reachable"
        result.exitCode() == 1
        sink.out().contains("CRITICAL: VULN-POS")
        sink.out().contains("REACHABLE")
        def json = mapper.readTree(work.resolve("reachability-report.json").toFile())
        json.get("metadata").get("callGraphBuilder").asText() == "SPARK"
    }

    def "given an unwritable report destination when analyzed then exit three with the write error"() {
        given:
        def sink = new CapturingSink()
        def readonlyDir = work.resolve("readonly")
        Files.createDirectories(readonlyDir)
        TestPermissions.withoutOwnerWrite(readonlyDir)
        def request = new AnalysisRequest(
                Path.of(MINI_APP_CLASSES),
                miniAppCpFile(),
                Path.of(BOM_MINI),
                Path.of(OSV_MINI),
                Optional.empty(),
                Optional.of(Path.of(MAPPINGS)),
                CallGraphPolicy.RTA,
                List.of(),
                Map.of(),
                Optional.empty())

        when:
        def result = AnalyzerEngine.analyze(request, readonlyDir.resolve("reachability-report"),
                [ReportFormat.JSON], false, sink)

        then:
        result.exitCode() == 3
        sink.err().contains("cannot write report")
    }

    def "given verbose mode when analyzed then the sink carries the diagnostics and the report summary"() {
        given:
        def sink = new CapturingSink()

        when:
        AnalyzerEngine.analyze(request(), work.resolve("reachability-report"),
                [ReportFormat.JSON], true, sink)

        then:
        sink.out().contains("Detected entry points:")
        sink.out().contains("call graph (RTA):")
        sink.out().contains("reports written: ")
        sink.out().contains("analysis took ")
    }
}
