package org.reachability.analyzer.report

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import org.reachability.analyzer.analysis.TestPermissions
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * M7c: the SARIF 2.1.0 findings writer (A9) — golden-file byte equality,
 * structural pins (one rule per distinct candidate id, a result per
 * REACHABLE only, the trace as message text, the purl as artifact
 * location, one logical location per hop — without duplicate items), the
 * dedup and empty-report edges, and the non-writable destination.
 */
class SarifReportWriterSpec extends Specification {

    private static final ObjectMapper MAPPER = new ObjectMapper()
    private static final File GOLDEN = new File("src/test/resources/fixtures/reports/reachability-report.golden.sarif")

    @TempDir
    Path workDir

    private static AnalysisReport fixedReport() {
        def metadata = new AnalysisReport.ReportMetadata(
                "0.1.0-SNAPSHOT", "RTA", 3, 27, 44, 382, 61,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 2)
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

    def "given the fixed report when written then the output matches the committed golden file"() {
        given:
        def file = workDir.resolve("report.sarif")

        when:
        new SarifReportWriter().write(fixedReport(), file)

        then: "byte-stable output: same model in, same bytes out"
        new String(Files.readAllBytes(file)).trim() == new String(Files.readAllBytes(GOLDEN.toPath())).trim()
    }

    def "given the golden file when parsed then the SARIF 2.1.0 structure holds field for field"() {
        given:
        def report = fixedReport()

        when:
        def node = MAPPER.readTree(GOLDEN)

        then: "the document header"
        node.get("version").asText() == "2.1.0"
        node.get('$schema').asText().contains("sarif-schema-2.1.0")

        and: "one run, one driver named after the tool with its version"
        node.get("runs").size() == 1
        def run = node.get("runs").get(0)
        run.get("tool").get("driver").get("name").asText() == "reachability-analyzer"
        run.get("tool").get("driver").get("version").asText() == report.metadata().toolVersion()

        and: "one rule per candidate, in entry order, with the OSV summary as fullDescription"
        def rules = run.get("tool").get("driver").get("rules")
        rules.size() == report.vulnerabilities().size()
        (0..<report.vulnerabilities().size()).every { i ->
            def rule = rules.get(i)
            def entry = report.vulnerabilities().get(i)
            rule.get("id").asText() == entry.id() &&
                    rule.get("name").asText() == entry.id() &&
                    rule.get("fullDescription").get("text").asText() == entry.summary()
        }

        and: "properties only when the record carries severity (the first severity string)"
        rules.get(0).get("properties").get("severity").asText() == report.vulnerabilities().get(0).severity()[0]
        !rules.get(1).has("properties")
        rules.get(2).get("properties").get("severity").asText() == "HIGH"

        and: "exactly one result - the REACHABLE entry only - with the trace as the message"
        def results = run.get("results")
        results.size() == 1
        def result = results.get(0)
        result.get("ruleId").asText() == "VULN-POS"
        result.get("level").asText() == "error"
        result.get("message").get("text").asText() == "demo.MainDanger#main -> stublib.Stub#danger"

        and: "the location pins the component purl and carries one logical location per path hop"
        def location = result.get("locations").get(0)
        location.get("physicalLocation").get("artifactLocation").get("uri").asText() ==
                "pkg:maven/stublib/stublib@1.0"
        def logical = location.get("logicalLocations")
        logical.size() == 2
        logical.get(0).get("name").asText() == "demo.MainDanger#main"
        logical.get(1).get("name").asText() == "stublib.Stub#danger"
    }

    def "given two reachable entries with the same vuln id when written then one rule but both results"() {
        given: "one vuln record hitting two components; the second has no declared version"
        def metadata = new AnalysisReport.ReportMetadata("0.1.0-SNAPSHOT", "RTA", 1, 5, 9, 12, null, null, 0)
        def entries = [
                new AnalysisReport.VulnerabilityEntry("DUP", "pkg:maven/g/h@1.0", "g:h", "1.0",
                        "REACHABLE", true, "Duplicate fixture vulnerability", ["HIGH"], "versions",
                        ["demo.Main#main", "stublib.Stub#danger"]),
                new AnalysisReport.VulnerabilityEntry("DUP", "pkg:maven/g/h@2.0", "g:h", null,
                        "REACHABLE", true, "Duplicate fixture vulnerability", ["HIGH"], "versions",
                        ["demo.Main#main", "stublib.Stub#danger"])]
        def file = workDir.resolve("dup.sarif")

        when:
        new SarifReportWriter().write(new AnalysisReport(metadata, entries), file)
        def node = MAPPER.readTree(file.toFile())
        def driver = node.get("runs").get(0).get("tool").get("driver")

        then: "the rule is deduped by id (the first entry's component text, version omitted when null)"
        driver.get("rules").size() == 1
        def rule = driver.get("rules").get(0)
        rule.get("id").asText() == "DUP"
        rule.get("shortDescription").get("text").asText() == "g:h 1.0 is affected by DUP"

        and: "both components stay findings"
        node.get("runs").get(0).get("results").size() == 2
    }

    def "given a path that repeats a hop display name when written then the logical locations carry no duplicate"() {
        given: "a bridge-style trace: two distinct methods share one display name" +
                " (log4j's static LoggerConfig#log(LoggerConfig, LogEvent) helper and the" +
                " instance LoggerConfig#log(LogEvent) both render as 'LoggerConfig#log')"
        def metadata = new AnalysisReport.ReportMetadata("0.1.0-SNAPSHOT", "RTA", 1, 5, 9, 12, null, null, 0)
        def path = ["com.example.demo.App#main", "LoggerConfig#log", "LoggerConfig#log", "LoggerConfig#processLogEvent"]
        def entries = [
                new AnalysisReport.VulnerabilityEntry("VULN-DUP-HOP",
                        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "org.apache.logging.log4j:log4j-core", "2.14.1", "REACHABLE", true,
                        "Repeated-hop fixture vulnerability", [], "versions", path)]
        def file = workDir.resolve("dup-hop.sarif")

        when:
        new SarifReportWriter().write(new AnalysisReport(metadata, entries), file)
        def result = MAPPER.readTree(file.toFile()).get("runs").get(0).get("results").get(0)

        then: "the full trace (repeated hop included) stays in the message text"
        result.get("message").get("text").asText() == path.join(" -> ")

        and: "the logical locations keep the order but drop the repeated item" +
                " (a duplicate item in one location makes the GitHub upload action reject the whole report)"
        def logical = result.get("locations").get(0).get("logicalLocations")
        def names = (0..<logical.size()).collect { logical.get(it).get("name").asText() }
        names == ["com.example.demo.App#main", "LoggerConfig#log", "LoggerConfig#processLogEvent"]
    }

    def "given a report with no candidates when written then a valid document with no rules or results"() {
        given:
        def metadata = new AnalysisReport.ReportMetadata("0.1.0-SNAPSHOT", "RTA", 1, 5, 9, 12, null, null, 0)
        def file = workDir.resolve("empty.sarif")

        when:
        new SarifReportWriter().write(new AnalysisReport(metadata, []), file)
        def node = MAPPER.readTree(file.toFile())
        def run = node.get("runs").get(0)

        then:
        node.get("version").asText() == "2.1.0"
        run.get("tool").get("driver").get("rules").isEmpty()
        run.get("results").isEmpty()
    }

    def "given a non-writable destination when writing then an IOException is thrown"() {
        given:
        def dir = workDir.resolve("readonly")
        Files.createDirectories(dir)
        TestPermissions.withoutOwnerWrite(dir)

        when:
        new SarifReportWriter().write(fixedReport(), dir.resolve("report.sarif"))

        then:
        thrown(IOException)

        cleanup:
        TestPermissions.ownerReadWriteExecute(dir)
    }
}
