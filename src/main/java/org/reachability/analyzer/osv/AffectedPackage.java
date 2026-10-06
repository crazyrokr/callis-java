package org.reachability.analyzer.osv;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * One OSV {@code affected[]} entry: the affected artifact, its explicit
 * version list, and its version ranges.
 *
 * <p>{@code name} is the raw OSV name (for Maven: {@code group:artifact} in
 * the dominant case, a plain name otherwise); {@code purl} is the purl the
 * record carries, when it has one.
 */
public record AffectedPackage(String name, String purl,
                              List<String> versions, List<VersionRange> ranges) {

    public AffectedPackage {
        versions = List.copyOf(versions);
        ranges = List.copyOf(ranges);
    }

    /**
     * Index keys for this entry: the raw name and, when the name is
     * {@code group:artifact}, its purl form {@code group/artifact}. A plain
     * name yields a single key.
     */
    public Set<String> nameKeys() {
        Set<String> keys = new LinkedHashSet<>();
        keys.add(name);
        keys.add(name.replace(':', '/'));
        return keys;
    }
}
