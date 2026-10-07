package org.reachability.analyzer.report;

import org.reachability.analyzer.report.AnalysisReport.VulnerabilityEntry;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/**
 * M5 T53: writes the report as JUnit XML — one {@code <testsuite
 * name="reachability">} and one {@code <testcase>} per candidate. A
 * REACHABLE vulnerability is a {@code <failure>} with the call trace in
 * the body; an unreachable one passes with a {@code <skipped>} note.
 * The suite therefore fails exactly when the pipeline must fail (exit 1),
 * keeping CI badges honest.
 */
public final class JUnitXmlReportWriter {

    private static final String REACHABLE = "REACHABLE";

    public void write(AnalysisReport report, Path file) throws IOException {
        Files.writeString(file, render(report));
    }

    private static String render(AnalysisReport report) {
        List<VulnerabilityEntry> entries = report.vulnerabilities();
        long failures = entries.stream().filter(entry -> REACHABLE.equals(entry.verdict())).count();
        StringBuilder out = new StringBuilder();
        out.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.append("<testsuite name=\"reachability\" tests=\"").append(entries.size())
                .append("\" failures=\"").append(failures)
                .append("\" errors=\"0\" skipped=\"").append(entries.size() - failures)
                .append("\" time=\"")
                .append(String.format(Locale.ROOT, "%.3f", report.metadata().durationMillis() / 1000.0))
                .append("\">\n");
        for (VulnerabilityEntry entry : entries) {
            out.append("  <testcase name=\"").append(escape(entry.id() + " " + entry.purl()))
                    .append("\" classname=\"reachability\">\n");
            if (REACHABLE.equals(entry.verdict())) {
                out.append("    <failure message=\"reachable\">\n");
                out.append("      ").append(escape(String.join(" -> ", entry.path()))).append("\n");
                out.append("    </failure>\n");
            } else {
                out.append("    <skipped message=\"").append(escape(skippedNote(entry))).append("\"/>\n");
            }
            out.append("  </testcase>\n");
        }
        out.append("</testsuite>");
        return out.toString();
    }

    private static String skippedNote(VulnerabilityEntry entry) {
        if (entry.onClasspath()) {
            return "unreachable: artifact present in classpath but no static path found"
                    + " - possible reflection/dynamic dispatch risk";
        }
        return "unreachable: artifact not on classpath - no class info";
    }

    private static String escape(String value) {
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
