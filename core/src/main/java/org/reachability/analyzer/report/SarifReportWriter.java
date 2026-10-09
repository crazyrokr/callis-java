package org.reachability.analyzer.report;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.reachability.analyzer.report.AnalysisReport.VulnerabilityEntry;

import java.io.IOException;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * M7c (A9): writes the report as SARIF 2.1.0 — the findings document for
 * CI code-scanning UIs. One rule per distinct candidate id (the OSV
 * record's summary as {@code fullDescription}); a {@code results[]} entry
 * per REACHABLE vulnerability only — level {@code error}, the call trace
 * as the message, the component purl as the artifact location, one
 * logical location per path hop. UNREACHABLE candidates stay out of a
 * findings document; the JUnit XML carries the full verdicts.
 */
public final class SarifReportWriter {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String REACHABLE = "REACHABLE";

    public void write(AnalysisReport report, Path file) throws IOException {
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(file.toFile(), toNode(report));
    }

    private static ObjectNode toNode(AnalysisReport report) {
        ObjectNode root = MAPPER.createObjectNode();
        root.put("$schema",
                "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/schemata/sarif-schema-2.1.0.json");
        root.put("version", "2.1.0");

        ObjectNode driver = MAPPER.createObjectNode();
        driver.put("name", "reachability-analyzer");
        driver.put("version", report.metadata().toolVersion());
        driver.set("rules", rulesNode(report.vulnerabilities()));
        ObjectNode tool = MAPPER.createObjectNode();
        tool.set("driver", driver);
        ObjectNode run = MAPPER.createObjectNode();
        run.set("tool", tool);
        run.set("results", resultsNode(report.vulnerabilities()));
        ArrayNode runs = MAPPER.createArrayNode();
        runs.add(run);
        root.set("runs", runs);
        return root;
    }

    /** One rule per distinct candidate id — a single OSV record can hit several components. */
    private static ArrayNode rulesNode(List<VulnerabilityEntry> entries) {
        ArrayNode rules = MAPPER.createArrayNode();
        Map<String, VulnerabilityEntry> firstBy = new LinkedHashMap<>();
        for (VulnerabilityEntry entry : entries) {
            firstBy.putIfAbsent(entry.id(), entry);
        }
        for (VulnerabilityEntry entry : firstBy.values()) {
            ObjectNode rule = MAPPER.createObjectNode();
            rule.put("id", entry.id());
            rule.put("name", entry.id());
            rule.set("shortDescription", MAPPER.createObjectNode().put("text",
                    entry.component()
                            + (entry.componentVersion() != null ? " " + entry.componentVersion() : "")
                            + " is affected by " + entry.id()));
            rule.set("fullDescription", MAPPER.createObjectNode().put("text", entry.summary()));
            if (!entry.severity().isEmpty()) {
                ObjectNode properties = MAPPER.createObjectNode();
                properties.put("severity", entry.severity().get(0));
                rule.set("properties", properties);
            }
            rules.add(rule);
        }
        return rules;
    }

    private static ArrayNode resultsNode(List<VulnerabilityEntry> entries) {
        ArrayNode results = MAPPER.createArrayNode();
        for (VulnerabilityEntry entry : entries) {
            if (!REACHABLE.equals(entry.verdict())) {
                continue;
            }
            ObjectNode location = MAPPER.createObjectNode();
            ObjectNode physical = MAPPER.createObjectNode();
            physical.set("artifactLocation", MAPPER.createObjectNode().put("uri", entry.purl()));
            location.set("physicalLocation", physical);
            ArrayNode logical = MAPPER.createArrayNode();
            for (String hop : entry.path()) {
                logical.add(MAPPER.createObjectNode().put("name", hop));
            }
            location.set("logicalLocations", logical);
            ArrayNode locations = MAPPER.createArrayNode();
            locations.add(location);

            ObjectNode result = MAPPER.createObjectNode();
            result.put("ruleId", entry.id());
            result.put("level", "error");
            result.set("message", MAPPER.createObjectNode().put("text", String.join(" -> ", entry.path())));
            result.set("locations", locations);
            results.add(result);
        }
        return results;
    }
}
