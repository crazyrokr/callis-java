package org.reachability.analyzer.engine

import spock.lang.Specification

/**
 * Fixed-width console tables: guards the two-space column separator and the
 * width rule (each column is padded to its widest cell across header and rows,
 * so columns stay aligned regardless of header vs data length).
 */
class TablePrinterSpec extends Specification {

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
    }

    def "given a header and rows whose data is wider than the header when printed then every column is padded to its widest cell"() {
        given:
        def sink = new CapturingSink()

        when: "an ID/Name header over 1/22 and alice/bob rows"
        TablePrinter.print(sink, ["ID", "Name"] as String[], [["1", "alice"] as String[], ["22", "bob"] as String[]])

        then: "column 0 is 2 wide, column 1 is 5 wide (alice), two spaces between columns"
        sink.outLines == ["ID  Name   ", "1   alice  ", "22  bob    "]
    }

    def "given a header and no data rows when printed then only the header line is written"() {
        given:
        def sink = new CapturingSink()

        when:
        TablePrinter.print(sink, ["Only"] as String[], [])

        then:
        sink.outLines == ["Only  "]
    }

    def "given a single column whose value is wider than the header when printed then the value line is padded to the value width"() {
        given:
        def sink = new CapturingSink()

        when:
        TablePrinter.print(sink, ["K"] as String[], [["longvalue"] as String[]])

        then: "width expands to the 9-char value; the header is padded to match"
        sink.outLines == ["K          ", "longvalue  "]
    }
}
