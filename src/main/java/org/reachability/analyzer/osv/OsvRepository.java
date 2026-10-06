package org.reachability.analyzer.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.reachability.analyzer.sbom.Purl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * In-memory index over the local OSV snapshot directory (M2 T21).
 *
 * <p>Each {@code *.json} file is parsed as one record. Records are indexed
 * under every name form of every affected entry: the raw
 * {@code group:artifact} name and its purl form {@code group/artifact}
 * (verified 2026-10-06 against all 7,163 records of the current dump:
 * 5,471 of 5,674 affected entries are {@code group:artifact}, 203 plain).
 *
 * <p>Robustness (T21b/A14): a malformed record is warned, skipped, and
 * counted; withdrawn records are never indexed (counted separately). A
 * non-empty directory that yields zero valid records is the fail-safe the
 * CLI turns into exit 3.
 */
public final class OsvRepository {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, List<OsvRecord>> index = new TreeMap<>();
    private final List<String> warnings = new ArrayList<>();
    private int fileCount;
    private int malformedCount;
    private int withdrawnCount;
    private int validRecordCount;

    public OsvRepository(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            throw new IOException("OSV directory does not exist: " + directory);
        }
        for (Path file : jsonFiles(directory)) {
            fileCount++;
            OsvRecord record = tryParse(file);
            if (record == null) {
                malformedCount++;
                continue;
            }
            if (record.withdrawn()) {
                withdrawnCount++;
            }
            validRecordCount++;
            if (!record.withdrawn()) {
                indexRecord(record);
            }
        }
    }

    private List<Path> jsonFiles(Path directory) throws IOException {
        try (Stream<Path> files = Files.list(directory)) {
            return files
                    .filter(file -> fileName(file).endsWith(".json"))
                    .sorted(Comparator.comparing(OsvRepository::fileName))
                    .toList();
        }
    }

    /** Path.getFileName() is null for the filesystem root, which a listing never yields. */
    private static String fileName(Path file) {
        Path name = file.getFileName();
        return name == null ? "" : name.toString();
    }

    private OsvRecord tryParse(Path file) {
        try {
            JsonNode root = MAPPER.readTree(file.toFile());
            if (root.isNull()) {
                warnings.add("skipping malformed OSV record '" + file.getFileName() + "': file is JSON null");
                return null;
            }
            if (root.isMissingNode()) {
                warnings.add("skipping malformed OSV record '" + file.getFileName() + "': empty file");
                return null;
            }
            return OsvRecord.parse(root);
        } catch (IOException | OsvFormatException e) {
            warnings.add("skipping malformed OSV record '" + file.getFileName() + "': " + e.getMessage());
            return null;
        }
    }

    private void indexRecord(OsvRecord record) {
        for (AffectedPackage entry : record.affected()) {
            for (String key : entry.nameKeys()) {
                List<OsvRecord> records = index.computeIfAbsent(key, key1 -> new ArrayList<>());
                if (!records.contains(record)) {
                    records.add(record);
                }
            }
        }
    }

    /** Records whose id equals the given one, across all name keys. */
    public List<OsvRecord> recordsNamed(String key) {
        return List.copyOf(index.getOrDefault(key, List.of()));
    }

    /**
     * Records affecting the given purl: queried under the purl's
     * {@code group:name} form and its {@code group/name} form. A purl
     * without a namespace queries its plain name only, so it never matches
     * a group-qualified record of the same artifact name.
     */
    public List<OsvRecord> lookup(Purl purl) {
        List<String> keys = queryKeys(purl);
        List<OsvRecord> found = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String key : keys) {
            for (OsvRecord record : index.getOrDefault(key, List.of())) {
                if (seen.add(record.id())) {
                    found.add(record);
                }
            }
        }
        return found;
    }

    static List<String> queryKeys(Purl purl) {
        List<String> keys = new ArrayList<>();
        keys.add(purl.getQualifiedName());
        if (!purl.getNamespace().isEmpty()) {
            keys.add(purl.getNamespace() + "/" + purl.getName());
        }
        return keys;
    }

    public int fileCount() {
        return fileCount;
    }

    public int malformedCount() {
        return malformedCount;
    }

    public int withdrawnCount() {
        return withdrawnCount;
    }

    /** Records that parsed (including withdrawn ones). */
    public int validRecordCount() {
        return validRecordCount;
    }

    /** Non-withdrawn records actually in the index. */
    public int indexedRecordCount() {
        return validRecordCount - withdrawnCount;
    }

    public List<String> warnings() {
        return List.copyOf(warnings);
    }
}
