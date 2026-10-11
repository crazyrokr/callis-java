package org.reachability.analyzer.report;

import java.util.List;

/**
 * M5 T51: the full run report — run metadata plus one entry per
 * vulnerability candidate. The writers (T52/T53) render this model to
 * pretty JSON and JUnit XML.
 *
 * <p>{@code verdict} is REACHABLE or UNREACHABLE (the NO_CLASS_INFO state
 * reports as UNREACHABLE with onClasspath=false); {@code affectedRange} is
 * the matcher's evidence for why the component version is affected;
 * {@code severity} carries the OSV severity strings when the record has
 * them; {@code path} is the call trace when reachable.
 */
public record AnalysisReport(ReportMetadata metadata, List<VulnerabilityEntry> vulnerabilities) {

    public AnalysisReport {
        vulnerabilities = List.copyOf(vulnerabilities);
    }

    public record ReportMetadata(String toolVersion, String callGraphBuilder, int entryPointCount,
                                 int callGraphNodes, int callGraphCalls, long durationMillis,
                                 Integer maxBytecodeMajor, String osvSnapshotSha256,
                                 int osvSkippedRecords, String sbomFile) {
    }

    public record VulnerabilityEntry(String id, String purl, String component, String componentVersion,
                                     String verdict, boolean onClasspath, String summary,
                                     List<String> severity, String affectedRange, List<String> path) {
        public VulnerabilityEntry {
            severity = List.copyOf(severity);
            path = List.copyOf(path);
        }
    }
}
