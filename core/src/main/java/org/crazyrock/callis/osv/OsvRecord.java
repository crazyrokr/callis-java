package org.crazyrock.callis.osv;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A parsed OSV vulnerability record (one {@code *.json} file of the
 * extracted {@code Maven/all.zip} snapshot).
 *
 * <p>Parsing is strict: a record whose shape deviates from the OSV schema
 * (missing id, affected entries without a package name, events without a
 * version, events with two or no kinds) is rejected with
 * {@link OsvFormatException} — the repository skips and counts it (T21b).
 *
 * <p>Hint normalization: when an affected entry has no {@code fixed} event
 * anywhere but carries {@code database_specific.last_known_affected_version_range},
 * its upper bound is added to every range of the entry — {@code <= N} becomes
 * an inclusive {@code last_affected N}, {@code < N} an exclusive
 * {@code fixed N} (verified 2026-10-06: the current dump uses only those
 * two shapes, 2,394 and 172 entries).
 *
 * <p>Severity (M5): the top-level {@code severity} array is kept as
 * {@code "TYPE"} or {@code "TYPE: score"} strings; when absent, the
 * top-level {@code database_specific.severity} level (e.g. {@code CRITICAL})
 * is used. Severity is metadata — malformed entries are skipped, never
 * rejected.
 */
public record OsvRecord(String id, List<String> aliases, String summary,
                        String withdrawnAt, List<String> severities,
                        List<AffectedPackage> affected) {

    private static final Pattern UPPER_BOUND = Pattern.compile("<\\s*(=?)\\s*([0-9][0-9A-Za-z._\\-]*)");

    public OsvRecord {
        aliases = List.copyOf(aliases);
        severities = List.copyOf(severities);
        affected = List.copyOf(affected);
    }

    /** Withdrawn records exist in the dump (113) and are never indexed. */
    public boolean withdrawn() {
        return withdrawnAt != null;
    }

    public static OsvRecord parse(JsonNode root) {
        if (!root.isObject()) {
            throw new OsvFormatException("OSV record is not a JSON object");
        }
        JsonNode idNode = root.get("id");
        if (idNode == null || !idNode.isTextual() || idNode.asText().isEmpty()) {
            throw new OsvFormatException("OSV record has no id");
        }
        String id = idNode.asText();

        List<String> aliases = new ArrayList<>();
        for (JsonNode alias : root.path("aliases")) {
            if (alias.isTextual() && !alias.asText().isEmpty()) {
                aliases.add(alias.asText());
            }
        }
        String summary = root.hasNonNull("summary") ? root.get("summary").asText() : "";
        String withdrawnAt = parseWithdrawn(root.get("withdrawn"));
        List<String> severities = parseSeverities(root);

        JsonNode affectedNode = root.get("affected");
        if (affectedNode == null || !affectedNode.isArray() || affectedNode.isEmpty()) {
            throw new OsvFormatException(id + ": 'affected' must be a non-empty array");
        }
        List<AffectedPackage> affected = new ArrayList<>();
        for (JsonNode entry : affectedNode) {
            affected.add(parseAffected(id, entry));
        }
        return new OsvRecord(id, aliases, summary, withdrawnAt, severities, affected);
    }

    private static List<String> parseSeverities(JsonNode root) {
        List<String> severities = new ArrayList<>();
        for (JsonNode severity : root.path("severity")) {
            if (!severity.isObject()) {
                continue;
            }
            JsonNode type = severity.get("type");
            if (type == null || !type.isTextual() || type.asText().isEmpty()) {
                continue;
            }
            JsonNode score = severity.get("score");
            if (score != null && score.isTextual() && !score.asText().isEmpty()) {
                severities.add(type.asText() + ": " + score.asText());
            } else {
                severities.add(type.asText());
            }
        }
        if (severities.isEmpty()) {
            JsonNode databaseSpecific = root.get("database_specific");
            if (databaseSpecific != null && databaseSpecific.isObject()) {
                JsonNode level = databaseSpecific.get("severity");
                if (level != null && level.isTextual() && !level.asText().isEmpty()) {
                    severities.add(level.asText());
                }
            }
        }
        return severities;
    }

    private static String parseWithdrawn(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        if (node.isBoolean() && !node.asBoolean()) {
            return null;
        }
        return node.asText();
    }

    private static AffectedPackage parseAffected(String id, JsonNode entry) {
        if (!entry.isObject()) {
            throw new OsvFormatException(id + ": affected entry is not an object");
        }
        JsonNode packageNode = entry.get("package");
        if (packageNode == null || !packageNode.isObject()) {
            throw new OsvFormatException(id + ": affected entry has no package object");
        }
        JsonNode nameNode = packageNode.get("name");
        if (nameNode == null || !nameNode.isTextual() || nameNode.asText().isEmpty()) {
            throw new OsvFormatException(id + ": affected entry has no package name");
        }

        List<String> versions = new ArrayList<>();
        for (JsonNode version : entry.path("versions")) {
            if (version.isTextual() && !version.asText().isEmpty()) {
                versions.add(version.asText());
            }
        }
        return applyLastKnownAffectedHint(nameNode.asText(),
                packageNode.hasNonNull("purl") ? packageNode.get("purl").asText() : null,
                versions, parseRanges(id, entry.path("ranges")), lastKnownAffectedHint(entry));
    }

    private static List<VersionRange> parseRanges(String id, JsonNode rangesNode) {
        List<VersionRange> ranges = new ArrayList<>();
        for (JsonNode rangeNode : rangesNode) {
            if (!rangeNode.isObject()) {
                throw new OsvFormatException(id + ": range is not an object");
            }
            String type = rangeNode.hasNonNull("type") ? rangeNode.get("type").asText() : "ECOSYSTEM";
            JsonNode eventsNode = rangeNode.get("events");
            if (eventsNode == null || !eventsNode.isArray()) {
                throw new OsvFormatException(id + ": range has no events array");
            }
            List<VersionEvent> events = new ArrayList<>();
            for (JsonNode eventNode : eventsNode) {
                events.add(parseEvent(id, eventNode));
            }
            ranges.add(new VersionRange(type, events));
        }
        return ranges;
    }

    private static VersionEvent parseEvent(String id, JsonNode eventNode) {
        if (!eventNode.isObject()) {
            throw new OsvFormatException(id + ": event is not an object");
        }
        List<VersionEvent> found = new ArrayList<>();
        for (String type : new String[]{VersionEvent.INTRODUCED, VersionEvent.FIXED, VersionEvent.LAST_AFFECTED}) {
            JsonNode version = eventNode.get(type);
            if (version == null) {
                continue;
            }
            if (!version.isTextual() || version.asText().isEmpty()) {
                throw new OsvFormatException(id + ": event '" + type + "' has no version");
            }
            found.add(new VersionEvent(type, version.asText()));
        }
        if (found.size() != 1) {
            throw new OsvFormatException(id + ": event must carry exactly one of introduced/fixed/last_affected");
        }
        return found.get(0);
    }

    private static String lastKnownAffectedHint(JsonNode entry) {
        JsonNode databaseSpecific = entry.get("database_specific");
        if (databaseSpecific == null || !databaseSpecific.isObject()) {
            return null;
        }
        JsonNode hint = databaseSpecific.get("last_known_affected_version_range");
        if (hint == null || !hint.isTextual()) {
            return null;
        }
        return hint.asText();
    }

    private record UpperBound(String version, boolean inclusive) {
    }

    private static UpperBound parseUpperBound(String hint) {
        Matcher matcher = UPPER_BOUND.matcher(hint);
        if (!matcher.find()) {
            return null;
        }
        // group(1) is the empty string (not null) for a bare '<'
        return new UpperBound(matcher.group(2), !matcher.group(1).isEmpty());
    }

    private static AffectedPackage applyLastKnownAffectedHint(String name, String purl,
                                                              List<String> versions,
                                                              List<VersionRange> ranges, String hint) {
        boolean hasFixed = ranges.stream().anyMatch(range ->
                range.events().stream().anyMatch(event -> event.type().equals(VersionEvent.FIXED)));
        if (hint == null || ranges.isEmpty() || hasFixed) {
            return new AffectedPackage(name, purl, versions, ranges);
        }
        UpperBound bound = parseUpperBound(hint);
        if (bound == null) {
            return new AffectedPackage(name, purl, versions, ranges);
        }
        String type = bound.inclusive() ? VersionEvent.LAST_AFFECTED : VersionEvent.FIXED;
        List<VersionRange> hinted = new ArrayList<>();
        for (VersionRange range : ranges) {
            List<VersionEvent> events = new ArrayList<>(range.events());
            events.add(new VersionEvent(type, bound.version()));
            hinted.add(new VersionRange(range.type(), events));
        }
        return new AffectedPackage(name, purl, versions, hinted);
    }
}
