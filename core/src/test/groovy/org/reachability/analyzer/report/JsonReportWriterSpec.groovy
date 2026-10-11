package org.reachability.analyzer.report

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.reachability.analyzer.analysis.TestPermissions
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T52 tests (M5): byte-stable pretty-printed JSON — golden-file equality,
 * round-trip parse back to the model, null/empty field handling, and the
 * IOException path for a non-writable destination.
 */
class JsonReportWriterSpec extends Specification {

    private static final ObjectMapper MAPPER = new ObjectMapper()
    private static final File GOLDEN = new File("src/test/resources/fixtures/reports/reachability-report.golden.json")

    @TempDir
    Path workDir

    private static AnalysisReport fixedReport() {
        def metadata = new AnalysisReport.ReportMetadata(
                "0.1.0-SNAPSHOT", "RTA", 3, 27, 44, 382, 61,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 2, "bom-mini.json")
        def entries = [
                new AnalysisReport.VulnerabilityEntry("VULN-POS", "pkg:maven/stublib/stublib@1.0", "stublib", "1.0",
                        "REACHABLE", true, "Test vulnerability in the stublib fixture",
                        ["CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"],
                        "range#0 (introduced=0, fixed=2.0)", ["demo.MainDanger#main", "stublib.Stub#danger"]),
                new AnalysisReport.VulnerabilityEntry("VULN-NEG", "pkg:maven/stublib/stublib@1.0", "stublib", "1.0",
                        "UNREACHABLE", true, "Test vulnerability in the stublib fixture",
                        [], "versions", []),
                new AnalysisReport.VulnerabilityEntry("VULN-GONE", "pkg:maven/nope/Gone@1.0", "nope:Gone", "1.0",
                        "UNREACHABLE", false, "Summary of the gone fixture vulnerability", ["HIGH"],
                        "range#0 (introduced=0, last_affected=1.0)", [])]
        new AnalysisReport(metadata, entries)
    }

    /** Jackson arrays are Iterable, not Collection — collect via each. */
    private static List<String> nodeTexts(JsonNode array) {
        def out = new ArrayList<String>()
        array.each { out << it.asText() }
        out
    }

    def "given the fixed report when written then the output matches the committed golden file"() {
        given:
        def file = workDir.resolve("report.json")

        when:
        new JsonReportWriter().write(fixedReport(), file)

        then: "byte-stable output: same model in, same bytes out"
        new String(Files.readAllBytes(file)).trim() == new String(Files.readAllBytes(GOLDEN.toPath())).trim()
    }

    def "given the golden file when parsed then every value round-trips back to the model"() {
        given:
        def report = fixedReport()

        when:
        def node = MAPPER.readTree(new String(Files.readAllBytes(GOLDEN.toPath())))

        then: "top level: metadata first, vulnerabilities second (stable key order)"
        node.fieldNames().toList() == ["metadata", "vulnerabilities"]

        and: "metadata keys in declaration order, values intact"
        def meta = node.get("metadata")
        meta.fieldNames().toList() == ["toolVersion", "callGraphBuilder", "entryPointCount", "callGraphNodes",
                "callGraphCalls", "durationMillis", "maxBytecodeMajor", "osvSnapshotSha256", "osvSkippedRecords",
                "sbomFile"]
        meta.get("toolVersion").asText() == report.metadata().toolVersion()
        meta.get("callGraphBuilder").asText() == report.metadata().callGraphBuilder()
        meta.get("entryPointCount").asInt() == report.metadata().entryPointCount()
        meta.get("durationMillis").asLong() == report.metadata().durationMillis()
        meta.get("maxBytecodeMajor").asInt() == report.metadata().maxBytecodeMajor()
        meta.get("osvSnapshotSha256").asText() == report.metadata().osvSnapshotSha256()
        meta.get("osvSkippedRecords").asInt() == report.metadata().osvSkippedRecords()
        meta.get("sbomFile").asText() == report.metadata().sbomFile()

        and: "each entry round-trips field for field, in order"
        def vulnerabilities = node.get("vulnerabilities")
        vulnerabilities.size() == report.vulnerabilities().size()
        (0..<report.vulnerabilities().size()).every { i ->
            def json = vulnerabilities.get(i)
            def entry = report.vulnerabilities().get(i)
            json.fieldNames().toList() == ["id", "purl", "component", "componentVersion", "verdict",
                    "onClasspath", "summary", "severity", "affectedRange", "path"] &&
                    json.get("id").asText() == entry.id() &&
                    json.get("purl").asText() == entry.purl() &&
                    json.get("component").asText() == entry.component() &&
                    json.get("componentVersion").asText() == entry.componentVersion() &&
                    json.get("verdict").asText() == entry.verdict() &&
                    json.get("onClasspath").asBoolean() == entry.onClasspath() &&
                    json.get("summary").asText() == entry.summary() &&
                    nodeTexts(json.get("severity")) == entry.severity() &&
                    json.get("affectedRange").asText() == entry.affectedRange() &&
                    nodeTexts(json.get("path")) == entry.path()
        }
    }

    def "given null optional metadata when written then the fields are JSON nulls"() {
        given:
        def metadata = new AnalysisReport.ReportMetadata(
                "0.1.0-SNAPSHOT", "RTA", 1, 5, 9, 12, null, null, 0, null)
        def file = workDir.resolve("null-metadata.json")

        when:
        new JsonReportWriter().write(new AnalysisReport(metadata, []), file)
        def node = MAPPER.readTree(file.toFile())

        then: "absent values serialize as null, empty entries as an empty array"
        node.get("metadata").get("maxBytecodeMajor").isNull()
        node.get("metadata").get("osvSnapshotSha256").isNull()
        node.get("metadata").get("sbomFile").isNull()
        node.get("vulnerabilities").isArray()
        node.get("vulnerabilities").isEmpty()
    }

    def "given a non-writable destination when writing then an IOException is thrown"() {
        given:
        def dir = workDir.resolve("readonly")
        Files.createDirectories(dir)
        TestPermissions.withoutOwnerWrite(dir)

        when:
        new JsonReportWriter().write(fixedReport(), dir.resolve("report.json"))

        then:
        thrown(IOException)

        cleanup:
        TestPermissions.ownerReadWriteExecute(dir)
    }
}
