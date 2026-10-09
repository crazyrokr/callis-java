package org.reachability.analyzer.report

import org.reachability.analyzer.analysis.TestPermissions
import org.w3c.dom.Document
import spock.lang.Specification
import spock.lang.TempDir

import javax.xml.parsers.DocumentBuilderFactory
import java.io.StringReader
import java.nio.file.Files
import java.nio.file.Path
import org.xml.sax.InputSource

/**
 * T53 tests (M5): JUnit XML semantics — one testsuite "reachability", one
 * testcase per candidate; REACHABLE is a <failure>, UNREACHABLE passes with
 * a <skipped> note, so the suite fails exactly when the pipeline must fail
 * (exit 1). Golden-file equality plus DOM well-formedness/semantics per
 * verdict, XML escaping, and the IOException path.
 */
class JUnitXmlReportWriterSpec extends Specification {

    private static final File GOLDEN = new File("src/test/resources/fixtures/reports/reachability-report.golden.xml")

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

    private static Document parse(String xml) {
        def factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)))
    }

    def "given the fixed report when written then the output matches the committed golden file"() {
        given:
        def file = workDir.resolve("report.xml")

        when:
        new JUnitXmlReportWriter().write(fixedReport(), file)

        then:
        new String(Files.readAllBytes(file)).trim() == new String(Files.readAllBytes(GOLDEN.toPath())).trim()
    }

    def "given the golden file when parsed then the suite and per-verdict semantics hold"() {
        when:
        def doc = parse(new String(Files.readAllBytes(GOLDEN.toPath())))
        def suite = doc.documentElement

        then: "the suite fails exactly because one of three candidates is reachable"
        suite.tagName == "testsuite"
        suite.getAttribute("name") == "reachability"
        suite.getAttribute("tests") == "3"
        suite.getAttribute("failures") == "1"
        suite.getAttribute("errors") == "0"
        suite.getAttribute("skipped") == "2"
        suite.getAttribute("time") == "0.382"

        and: "the REACHABLE entry is a failure with the call path in the body"
        def reachable = suite.getElementsByTagName("testcase").item(0)
        reachable.getAttribute("name") == "VULN-POS pkg:maven/stublib/stublib@1.0"
        reachable.getAttribute("classname") == "reachability"
        def failure = reachable.getElementsByTagName("failure").item(0)
        failure.getAttribute("message") == "reachable"
        failure.textContent.trim() == "demo.MainDanger#main -> stublib.Stub#danger"

        and: "the UNREACHABLE entries pass with skipped notes matched to their state"
        def neg = suite.getElementsByTagName("testcase").item(1)
        neg.getElementsByTagName("failure").length == 0
        neg.getElementsByTagName("skipped").item(0).getAttribute("message")
                .contains("artifact present in classpath")
        def gone = suite.getElementsByTagName("testcase").item(2)
        gone.getElementsByTagName("failure").length == 0
        gone.getElementsByTagName("skipped").item(0).getAttribute("message")
                .contains("artifact not on classpath")
    }

    def "given a report without reachable vulnerabilities when written then the suite has no failures"() {
        given:
        def entries = [new AnalysisReport.VulnerabilityEntry("VULN-NEG", "pkg:maven/stublib/stublib@1.0", "stublib",
                "1.0", "UNREACHABLE", true, "Test vulnerability in the stublib fixture", [], "versions", [])]
        def file = workDir.resolve("pass.xml")

        when:
        new JUnitXmlReportWriter().write(new AnalysisReport(fixedReport().metadata(), entries), file)
        def suite = parse(new String(Files.readAllBytes(file))).documentElement

        then: "a green suite mirrors the pipeline's exit 0"
        suite.getAttribute("tests") == "1"
        suite.getAttribute("failures") == "0"
        suite.getAttribute("skipped") == "1"
    }

    def "given an empty report when written then the suite carries no testcases"() {
        given:
        def file = workDir.resolve("empty.xml")

        when:
        new JUnitXmlReportWriter().write(new AnalysisReport(fixedReport().metadata(), []), file)
        def suite = parse(new String(Files.readAllBytes(file))).documentElement

        then:
        suite.getAttribute("tests") == "0"
        suite.getAttribute("failures") == "0"
        suite.getElementsByTagName("testcase").length == 0
    }

    def "given special characters in the vuln id when written then they are escaped and the xml stays well-formed"() {
        given:
        def entry = new AnalysisReport.VulnerabilityEntry('A&B<C>D"E\'F', "pkg:maven/g/h@1.0", "g:h", "1.0",
                "REACHABLE", true, "Escaped fixture vulnerability", [], "versions", ["a#b"])
        def file = workDir.resolve("escaped.xml")

        when:
        new JUnitXmlReportWriter().write(new AnalysisReport(fixedReport().metadata(), [entry]), file)
        def raw = new String(Files.readAllBytes(file))

        then: "all five XML specials are escaped in the raw text"
        raw.contains("A&amp;B&lt;C&gt;D&quot;E&apos;F")
        !raw.contains("A&B<C>D")

        and: "the escaped xml still parses and the attribute round-trips"
        def doc = parse(raw)
        doc.getElementsByTagName("testcase").item(0).getAttribute("name") == 'A&B<C>D"E\'F pkg:maven/g/h@1.0'
    }

    def "given a non-writable destination when writing then an IOException is thrown"() {
        given:
        def dir = workDir.resolve("readonly")
        Files.createDirectories(dir)
        TestPermissions.withoutOwnerWrite(dir)

        when:
        new JUnitXmlReportWriter().write(fixedReport(), dir.resolve("report.xml"))

        then:
        thrown(IOException)

        cleanup:
        TestPermissions.ownerReadWriteExecute(dir)
    }
}
