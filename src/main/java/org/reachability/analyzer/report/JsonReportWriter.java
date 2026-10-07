package org.reachability.analyzer.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.reachability.analyzer.report.AnalysisReport.ReportMetadata;
import org.reachability.analyzer.report.AnalysisReport.VulnerabilityEntry;

import java.io.IOException;
import java.nio.file.Path;

/**
 * M5 T52: writes the report as pretty-printed JSON. Key order is the
 * model's declaration order (Jackson ObjectNodes keep insertion order), so
 * identical runs produce byte-identical files.
 */
public final class JsonReportWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public void write(AnalysisReport report, Path file) throws IOException {
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), toNode(report));
    }

    private static ObjectNode toNode(AnalysisReport report) {
        ObjectNode root = MAPPER.createObjectNode();
        root.set("metadata", metadataNode(report.metadata()));
        ArrayNode vulnerabilities = MAPPER.createArrayNode();
        for (VulnerabilityEntry entry : report.vulnerabilities()) {
            vulnerabilities.add(entryNode(entry));
        }
        root.set("vulnerabilities", vulnerabilities);
        return root;
    }

    private static ObjectNode metadataNode(ReportMetadata metadata) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("toolVersion", metadata.toolVersion());
        node.put("callGraphBuilder", metadata.callGraphBuilder());
        node.put("entryPointCount", metadata.entryPointCount());
        node.put("callGraphNodes", metadata.callGraphNodes());
        node.put("callGraphCalls", metadata.callGraphCalls());
        node.put("durationMillis", metadata.durationMillis());
        if (metadata.maxBytecodeMajor() != null) {
            node.put("maxBytecodeMajor", metadata.maxBytecodeMajor());
        } else {
            node.putNull("maxBytecodeMajor");
        }
        if (metadata.osvSnapshotSha256() != null) {
            node.put("osvSnapshotSha256", metadata.osvSnapshotSha256());
        } else {
            node.putNull("osvSnapshotSha256");
        }
        node.put("osvSkippedRecords", metadata.osvSkippedRecords());
        return node;
    }

    private static ObjectNode entryNode(VulnerabilityEntry entry) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put("id", entry.id());
        node.put("purl", entry.purl());
        node.put("component", entry.component());
        node.put("componentVersion", entry.componentVersion());
        node.put("verdict", entry.verdict());
        node.put("onClasspath", entry.onClasspath());
        ArrayNode severity = MAPPER.createArrayNode();
        for (String value : entry.severity()) {
            severity.add(value);
        }
        node.set("severity", severity);
        node.put("affectedRange", entry.affectedRange());
        ArrayNode path = MAPPER.createArrayNode();
        for (String hop : entry.path()) {
            path.add(hop);
        }
        node.set("path", path);
        return node;
    }
}
