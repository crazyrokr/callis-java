package org.crazyrock.callis.analysis;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * T42: loads the optional vuln-mappings.json — a strict object that maps
 * vulnerability ids to lists of {@code {class, method[, descriptor]}}
 * entries, validated at startup before any analysis runs.
 *
 * <p>The optional {@code descriptor} is a source-style parameter list
 * (e.g. {@code "()"}): it narrows the match to one overload. A malformed
 * file is a usage error (exit 2 upstream); a missing file is an IOException.
 */
public final class VulnMappingLoader {

    /** One mapping entry: fully qualified class name, method name, optional descriptor. */
    public record VulnTarget(String className, String methodName, String descriptor) {
    }

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * @throws IOException when the file is missing or unreadable
     * @throws VulnMappingFormatException when the structure is not the expected object mapping
     */
    public Map<String, List<VulnTarget>> load(Path file) throws IOException {
        JsonNode root = MAPPER.readTree(Files.newInputStream(file));
        if (root == null || !root.isObject()) {
            throw new VulnMappingFormatException("malformed vuln-mappings file " + fileName(file)
                    + ": root must be a JSON object mapping vulnerability id to target list");
        }
        TreeMap<String, List<VulnTarget>> result = new TreeMap<>();
        ObjectNode object = (ObjectNode) root;
        for (Map.Entry<String, JsonNode> field : object.properties()) {
            JsonNode entries = field.getValue();
            if (entries == null || !entries.isArray()) {
                throw new VulnMappingFormatException("malformed vuln-mappings file " + fileName(file)
                        + ": value of " + field.getKey()
                        + " must be a list of {class, method[, descriptor]} entries");
            }
            List<VulnTarget> targets = new ArrayList<>();
            for (JsonNode entry : entries) {
                if (entry == null || !entry.isObject()) {
                    throw new VulnMappingFormatException("malformed vuln-mappings file " + fileName(file)
                            + ": each entry of " + field.getKey() + " must be a JSON object");
                }
                String className = text(entry, "class");
                if (className == null || className.isEmpty()) {
                    throw new VulnMappingFormatException("malformed vuln-mappings file " + fileName(file)
                            + ": entry of " + field.getKey() + " is missing the required \"class\" field");
                }
                String methodName = text(entry, "method");
                if (methodName == null || methodName.isEmpty()) {
                    throw new VulnMappingFormatException("malformed vuln-mappings file " + fileName(file)
                            + ": entry of " + field.getKey() + " is missing the required \"method\" field");
                }
                String descriptor = text(entry, "descriptor");
                targets.add(new VulnTarget(className, methodName,
                        descriptor == null || descriptor.isBlank() ? null : descriptor));
            }
            result.put(field.getKey(), List.copyOf(targets));
        }
        return result;
    }

    private static String fileName(Path path) {
        Path name = path.getFileName();
        return name == null ? path.toString() : name.toString();
    }

    /** Text field value, or null when absent, null-typed, or non-textual. */
    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || !value.isTextual()) {
            return null;
        }
        return value.asText().trim();
    }
}
