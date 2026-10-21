package org.crazyrock.callis.osv;

import java.util.List;

/** One OSV affected range: a type (ECOSYSTEM/SEMVER) plus its event list. */
public record VersionRange(String type, List<VersionEvent> events) {

    public VersionRange {
        events = List.copyOf(events);
    }
}
