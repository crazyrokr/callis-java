package org.reachability.analyzer.osv

import com.fasterxml.jackson.databind.ObjectMapper
import spock.lang.Specification

import java.util.List

/**
 * Unit tests for the pure version-range engine (M2 T22). One where-table per
 * event-shape family; the false-positive guard (version == fixed is NOT
 * affected) is pinned in several families, per the plan's test strategy.
 */
class VersionRangeMatcherSpec extends Specification {

    static VersionEvent ev(String type, String version) {
        new VersionEvent(type, version)
    }

    static VersionRange range(List<VersionEvent> events) {
        new VersionRange("ECOSYSTEM", events)
    }

    static AffectedPackage entry(List<String> versions, List<VersionRange> ranges) {
        new AffectedPackage("g:n", null, versions, ranges)
    }

    def "given introduced 0 and fixed 2.15.0 when the version is inside or at the boundary then only inside versions are affected"() {
        given:
        def e = entry([], [range([ev("introduced", "0"), ev("fixed", "2.15.0")])])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version   | affected
        "0"       | true
        "2.13.0"  | true   // introduced is inclusive
        "2.14.1"  | true
        "2.15.0"  | false  // fixed is exclusive (false-positive guard)
        "2.16.0"  | false
    }

    def "given a range without fixed when the version is at or above introduced then it is affected without upper bound"() {
        given:
        def e = entry([], [range([ev("introduced", "2.13.0")])])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version  | affected
        "2.12.9" | false
        "2.13.0" | true
        "2.99.0" | true
    }

    def "given last_affected 1.12.0 when the version is at or below the boundary then only lower versions are affected"() {
        given:
        def e = entry([], [range([ev("introduced", "0"), ev("last_affected", "1.12.0")])])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version  | affected
        "1.10.0" | true
        "1.11.0" | true
        "1.12.0" | true   // last_affected is inclusive
        "1.12.1" | false  // strictly greater is not affected
    }

    def "given multiple ranges on one entry when a version matches any range then it is affected (OR semantics)"() {
        given:
        def e = entry([], [range([ev("introduced", "0"), ev("fixed", "2.3.1")]),
                          range([ev("introduced", "2.4"), ev("fixed", "2.12.2")])])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version  | affected
        "2.0"    | true   // first range
        "2.3.1"  | false  // at fixed of first, below introduced of second
        "2.11.0" | true   // second range
        "2.13.0" | false  // above both
    }

    def "given a version matching both the versions list and a range then evidence carries both"() {
        given:
        def e = entry(["1.5"], [range([ev("introduced", "1.0"), ev("fixed", "2.0")])])

        expect:
        def evidence = VersionRangeMatcher.matchedBy("1.5", e)
        evidence.contains("versions")
        evidence.any { it.startsWith("range#0") }
    }

    def "given maven oddball qualifiers when compared against fixed 1.0 then ordering follows Maven ComparableVersion"() {
        given:
        def e = entry([], [range([ev("introduced", "0"), ev("fixed", "1.0")])])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version         | affected
        "0.9"           | true
        "1.0-alpha1"    | true   // alpha sorts below release
        "1.0-SNAPSHOT"  | true   // snapshot sorts below release
        "1.0"           | false  // == fixed
        "1.0-RELEASE"   | false  // release == 1.0
        "1.0.0"         | false  // 1.0.0 == 1.0 in Maven ordering
        "1.0.1"         | false
    }

    def "given a version equal to fixed when matched then it is not affected and evidence is empty"() {
        given:
        def e = entry([], [range([ev("introduced", "0"), ev("fixed", "2.15.0")])])

        expect:
        !VersionRangeMatcher.isAffected("2.15.0", e)
        VersionRangeMatcher.matchedBy("2.15.0", e).isEmpty()
    }

    def "given an entry with only a versions list when the version is in or out of the list then membership decides"() {
        given:
        def e = entry(["1.0", "2.0", "2.6.3-CUSTOM"], [])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version          | affected
        "1.0"            | true
        "1.5"            | false
        "2.6.3-CUSTOM"   | true   // exact string match, no normalization
        "2.6.3-custom"   | false
    }

    def "given a range with no events when matched then nothing is affected (conservative)"() {
        given:
        def e = entry([], [range([])])

        expect:
        !VersionRangeMatcher.isAffected("1.0", e)
        VersionRangeMatcher.matchedBy("1.0", e).isEmpty()
    }

    def "given a range carrying both fixed and last_affected when matched then both bounds constrain"() {
        given:
        def e = entry([], [range([ev("introduced", "0"), ev("fixed", "2.0"), ev("last_affected", "1.5")])])

        expect:
        VersionRangeMatcher.isAffected(version, e) == affected

        where:
        version | affected
        "0.5"   | true
        "1.5"   | true   // <= last_affected and < fixed
        "1.6"   | false  // > last_affected
        "2.0"   | false  // == fixed
    }

    def "given evidence for a matching range when described then the events are listed"() {
        given:
        def e = entry([], [range([ev("introduced", "2.13.0"), ev("fixed", "2.15.0")]),
                          range([ev("introduced", "0"), ev("fixed", "2.3.1")])])

        when:
        def evidence = VersionRangeMatcher.matchedBy("2.14.1", e)

        then:
        evidence == ["range#0 (introduced=2.13.0, fixed=2.15.0)"]
    }

    def "given the real log4shell record when probed with 2.14.1 2.15.0 and 2.16.0 then only 2.14.1 is affected for log4j-core"() {
        given: "the first affected entry is org.apache.logging.log4j:log4j-core 2.13.0..2.15.0"
        def record = OsvRecord.parse(new ObjectMapper().readTree(new File("src/test/resources/fixtures/osv/GHSA-jfh8-c2jp-5v3q.json")))
        def core = record.affected().get(0)
        core.name == "org.apache.logging.log4j:log4j-core"

        expect:
        VersionRangeMatcher.isAffected(version, core) == affected

        where:
        version  | affected
        "2.14.1" | true
        "2.15.0" | false
        "2.16.0" | false
    }

    def "given the real last_affected entry (guicedee fork) when probed around the boundary then the inclusive bound holds"() {
        given: "the com.guicedee.services:log4j-core entry is introduced 0 .. last_affected 1.2.1.2-jre17"
        def record = OsvRecord.parse(new ObjectMapper().readTree(new File("src/test/resources/fixtures/osv/GHSA-jfh8-c2jp-5v3q.json")))
        def fork = record.affected().get(3)
        fork.name == "com.guicedee.services:log4j-core"

        expect:
        VersionRangeMatcher.isAffected(version, fork) == affected

        where:
        version            | affected
        "1.2.1.2-jre17"    | true   // at last_affected: inclusive
        "1.2.0.1-jre15"    | true
        "1.2.1.3"          | false  // above last_affected
    }
}
