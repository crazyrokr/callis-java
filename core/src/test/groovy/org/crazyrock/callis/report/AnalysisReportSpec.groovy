package org.crazyrock.callis.report

import spock.lang.Specification

/**
 * T51 model tests (M5): the report holds defensive copies of its lists, so
 * the CLI's mutable working lists cannot mutate a serialized report.
 */
class AnalysisReportSpec extends Specification {

    def "given mutable lists when the report is constructed then defensive copies are held"() {
        given:
        def path = ["a", "b"]
        def severity = ["HIGH"]
        def entry = new AnalysisReport.VulnerabilityEntry("V-1", "pkg:maven/g/h@1", "g:h", "1", "UNREACHABLE",
                true, "Summary of V-1", severity, "versions", path)
        def metadata = new AnalysisReport.ReportMetadata("0.1.0-SNAPSHOT", "RTA", 1, 2, 3, 4, 61,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", 0, null)
        def report = new AnalysisReport(metadata, [entry, entry])

        when: "the original lists are mutated after construction"
        path << "mutated"
        severity << "LOW"

        then:
        entry.path() == ["a", "b"]
        entry.severity() == ["HIGH"]
        report.metadata() == metadata
        report.vulnerabilities().size() == 2
        report.vulnerabilities()[0] == entry
    }

    def "given null-free accessors when read then the entry fields round-trip"() {
        given:
        def entry = new AnalysisReport.VulnerabilityEntry("V-2", "pkg:maven/x/y@2", "x:y", "2", "REACHABLE",
                true, "Summary of V-2", [], "versions", ["p#q"])

        expect:
        entry.id() == "V-2"
        entry.purl() == "pkg:maven/x/y@2"
        entry.component() == "x:y"
        entry.componentVersion() == "2"
        entry.verdict() == "REACHABLE"
        entry.onClasspath()
        entry.summary() == "Summary of V-2"
        entry.severity().isEmpty()
        entry.affectedRange() == "versions"
        entry.path() == ["p#q"]
    }
}
