package org.crazyrock.callis.osv;

import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Pure version-range engine (M2 T22): decides whether a component version
 * falls into an affected package's version list or ranges, with Maven
 * {@code ComparableVersion} ordering.
 *
 * <p>Semantics: {@code introduced} is inclusive, {@code fixed} is exclusive,
 * {@code last_affected} is inclusive; multiple ranges are OR; a range without
 * events matches nothing (conservative — a security gate must not guess);
 * the explicit versions list is exact string membership. A version equal to
 * {@code fixed} is <em>not</em> affected (the plan's false-positive guard).
 */
public final class VersionRangeMatcher {

    private VersionRangeMatcher() {
    }

    /** True when the version is in the versions list or inside any range. */
    public static boolean isAffected(String version, AffectedPackage entry) {
        return !matchedBy(version, entry).isEmpty();
    }

    /**
     * Human-readable evidence for the match: {@code "versions"} when the
     * explicit list hit, one {@code "range#N (...)"} entry per matching
     * range. Empty list when the version is not affected.
     */
    public static List<String> matchedBy(String version, AffectedPackage entry) {
        Objects.requireNonNull(version, "version");
        Objects.requireNonNull(entry, "entry");
        List<String> evidence = new ArrayList<>();
        if (entry.versions().contains(version)) {
            evidence.add("versions");
        }
        for (int i = 0; i < entry.ranges().size(); i++) {
            VersionRange range = entry.ranges().get(i);
            if (rangeMatches(version, range)) {
                evidence.add(describe(i, range));
            }
        }
        return evidence;
    }

    static boolean rangeMatches(String version, VersionRange range) {
        if (range.events().isEmpty()) {
            return false;
        }
        ComparableVersion v = new ComparableVersion(version);
        for (VersionEvent event : range.events()) {
            int comparison = v.compareTo(new ComparableVersion(event.version()));
            if (VersionEvent.INTRODUCED.equals(event.type()) && comparison < 0) {
                return false;
            }
            if (VersionEvent.FIXED.equals(event.type()) && comparison >= 0) {
                return false;
            }
            if (VersionEvent.LAST_AFFECTED.equals(event.type()) && comparison > 0) {
                return false;
            }
        }
        return true;
    }

    /** Only called for matching ranges, which always carry events. */
    static String describe(int index, VersionRange range) {
        String joined = range.events().stream()
                .map(VersionEvent::toString)
                .collect(Collectors.joining(", "));
        return "range#" + index + " (" + joined + ")";
    }
}
