package org.reachability.analyzer.osv

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.ObjectNode
import spock.lang.Specification

import java.util.List

/**
 * Unit tests for OSV record parsing (M2 T21), including the
 * last_known_affected_version_range hint and the malformed-record contract
 * (T21b: a malformed record must be rejectable, not guessed at).
 */
class OsvRecordSpec extends Specification {

    private static final ObjectMapper MAPPER = new ObjectMapper()

    private static ObjectNode obj() {
        MAPPER.createObjectNode()
    }

    private static ArrayNode arr(Object... values) {
        def node = MAPPER.createArrayNode()
        values.each { node.add(it) }
        return node
    }

    def "given the real log4shell record when parsed then id aliases and affected entries are captured"() {
        when:
        def record = OsvRecord.parse(MAPPER.readTree(new File("src/test/resources/fixtures/osv/GHSA-jfh8-c2jp-5v3q.json")))

        then:
        record.id() == "GHSA-jfh8-c2jp-5v3q"
        record.aliases() == ["CVE-2021-44228"]
        record.summary().contains("Log4j")
        record.withdrawnAt() == null
        !record.withdrawn()
        record.affected().size() == 10
        record.affected().get(0).name() == "org.apache.logging.log4j:log4j-core"
        record.affected().get(0).purl() == "pkg:maven/org.apache.logging.log4j/log4j-core"
        record.affected().get(0).versions().contains("2.14.1")
        record.affected().get(0).ranges().size() == 1
        def events = record.affected().get(0).ranges().get(0).events()
        events.contains(new VersionEvent("introduced", "2.13.0"))
        events.contains(new VersionEvent("fixed", "2.15.0"))
        record.severities() == ["CVSS_V3: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H"]
    }

    def "given the real withdrawn record when parsed then withdrawn is flagged"() {
        when:
        def record = OsvRecord.parse(MAPPER.readTree(new File("src/test/resources/fixtures/osv/GHSA-22c5-cpvr-cfvq.json")))

        then:
        record.id() == "GHSA-22c5-cpvr-cfvq"
        record.withdrawnAt() != null
        record.withdrawn()
    }

    def "given a record with last_known_affected_version_range and a fixed event when parsed then the hint is ignored"() {
        given: "GHSA-223m-pgcq-f3xg carries the hint '<= 22.1.38' but also a fixed event"
        def record = OsvRecord.parse(MAPPER.readTree(new File("src/test/resources/fixtures/osv/GHSA-223m-pgcq-f3xg.json")))
        def range = record.affected().get(0).ranges().get(0)

        expect:
        range.events() == [new VersionEvent("introduced", "0"), new VersionEvent("fixed", "22.2.39")]
    }

    def "given a record with the hint and no fixed event when parsed then an inclusive last_affected bound is added to every range"() {
        given:
        def node = recordWithAffected("g:n", [["introduced": "0"]], null, [last_known_affected_version_range: "<= 1.5"])

        when:
        def record = OsvRecord.parse(node)
        def events = record.affected().get(0).ranges().get(0).events()

        then:
        events == [new VersionEvent("introduced", "0"), new VersionEvent("last_affected", "1.5")]
    }

    def "given a record with an exclusive hint and no fixed event when parsed then an exclusive fixed bound is added"() {
        given:
        def node = recordWithAffected("g:n", [["introduced": "0"]], null, [last_known_affected_version_range: "< 1.6"])

        when:
        def record = OsvRecord.parse(node)
        def events = record.affected().get(0).ranges().get(0).events()

        then:
        events == [new VersionEvent("introduced", "0"), new VersionEvent("fixed", "1.6")]
    }

    def "given a record with two ranges and the hint when parsed then the hint is added to both ranges"() {
        given:
        def node = recordWithAffected("g:n", [["introduced": "0"], ["introduced": "2.0"]], null,
                [last_known_affected_version_range: "<= 3.0"])

        when:
        def record = OsvRecord.parse(node)

        then:
        record.affected().get(0).ranges().every {
            it.events().any { e -> e.type() == "last_affected" && e.version() == "3.0" }
        }
    }

    def "given a hint that cannot be parsed when parsed then the record is unchanged"() {
        given:
        def node = recordWithAffected("g:n", [["introduced": "0"]], null, [last_known_affected_version_range: "weird text"])

        when:
        def record = OsvRecord.parse(node)

        then:
        record.affected().get(0).ranges().get(0).events() == [new VersionEvent("introduced", "0")]
    }

    def "given a versions-only entry and the hint when parsed then no synthetic range is invented"() {
        given:
        def node = recordWithAffected("g:n", null, ["1.0", "1.1"], [last_known_affected_version_range: "<= 2.0"])

        when:
        def record = OsvRecord.parse(node)
        def entry = record.affected().get(0)

        then:
        entry.ranges().isEmpty()
        entry.versions() == ["1.0", "1.1"]
    }

    def "given a record without aliases or summary when parsed then empty defaults are used"() {
        given:
        def node = obj()
        node.put("id", "TEST-1")
        node.set("affected", arr(affectedEntry("g:n", [["introduced": "0"]], null, null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.aliases().isEmpty()
        record.summary() == ""
        record.withdrawnAt() == null
    }

    def "given a record with a boolean withdrawn false when parsed then it is not withdrawn"() {
        given:
        def node = obj()
        node.put("id", "TEST-2")
        node.put("withdrawn", false)
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.withdrawnAt() == null
        !record.withdrawn()
    }

    private static ObjectNode recordWithAffectedFull(String name, List eventsList, List versions, Map dbSpecific) {
        def node = obj()
        node.put("id", "GHSA-1")
        def entry = obj()
        def pkg = obj()
        pkg.put("name", name)
        entry.set("package", pkg)
        if (eventsList != null) {
            def ranges = MAPPER.createArrayNode()
            eventsList.each { evts ->
                def range = obj()
                range.put("type", "ECOSYSTEM")
                def events = MAPPER.createArrayNode()
                if (evts instanceof Map) {
                    evts.each { k, v -> events.add(obj().put(k as String, v as String)) }
                } else {
                    evts.each { ev -> events.add(ev as JsonNode) }
                }
                range.set("events", events)
                ranges.add(range)
            }
            entry.set("ranges", ranges)
        }
        if (versions != null) {
            entry.set("versions", arr(versions as Object[]))
        }
        if (dbSpecific != null) {
            def db = obj()
            dbSpecific.each { k, v -> db.set(k as String, v) }
            entry.set("database_specific", db)
        }
        node.set("affected", arr(entry))
        return node
    }

    /** Record with the given id node; affected may be null (absent). */
    private static ObjectNode record(JsonNode idNode, JsonNode affected) {
        def node = obj()
        node.set("id", idNode)
        if (affected != null) {
            node.set("affected", affected)
        }
        return node
    }

    /** Affected entry built from raw field values (statement form: this
     *  Jackson's ObjectNode.put(String, JsonNode) returns the value, not this). */
    private static ObjectNode entryWith(Map pkgFields, JsonNode ranges, JsonNode dbSpecific) {
        def entry = obj()
        def pkg = obj()
        pkgFields.each { k, v ->
            if (v instanceof JsonNode) {
                pkg.set(k as String, v as JsonNode)
            } else {
                pkg.put(k as String, v as String)
            }
        }
        entry.set("package", pkg)
        if (ranges != null) {
            entry.set("ranges", ranges)
        }
        if (dbSpecific != null) {
            entry.set("database_specific", dbSpecific)
        }
        return entry
    }

    private static ObjectNode rangeOf(JsonNode events) {
        def range = obj()
        range.put("type", "ECOSYSTEM")
        if (events != null) {
            range.set("events", events)
        }
        return range
    }

    private static ObjectNode eventWith(Map fields) {
        def event = obj()
        fields.each { k, v -> event.set(k as String, v) }
        return event
    }

    def "given malformed records when parsed then OsvFormatException with the expected message"() {
        when:
        OsvRecord.parse(node)

        then:
        def e = thrown(OsvFormatException)
        e.message.contains(messageFragment)

        where: "each shape is malformed per the OSV schema"
        node                                                                                                                                                   | messageFragment
        MAPPER.readTree("{}")                                                                                                                                  | "no id"
        record(MAPPER.getNodeFactory().nullNode(), arr(obj()))                                                                                                | "no id"
        record(MAPPER.getNodeFactory().textNode(""), arr(obj()))                                                                                              | "no id"
        record(MAPPER.getNodeFactory().numberNode(42), arr(obj()))                                                                                            | "no id"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), null)                                                                                               | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), MAPPER.getNodeFactory().nullNode())                                                                | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr())                                                                                              | "GHSA-1"
        MAPPER.readTree("[1]")                                                                                                                                | "not a JSON object"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), MAPPER.getNodeFactory().textNode("x"))                                                             | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(obj()))                                                                                        | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(MAPPER.getNodeFactory().textNode("x")))                                                        | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(obj().put("package", MAPPER.getNodeFactory().textNode("x"))))                                | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(entryWith([:], null, null)))                                                                   | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(entryWith([name: MAPPER.getNodeFactory().numberNode(42)], null, null)))                    | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(affectedEntry("g:n", [[obj()]], null, null)))                                                 | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(affectedEntry("g:n", [[obj().put("introduced", "1.0").put("fixed", "2.0")]], null, null))) | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(affectedEntry("g:n", [[obj().put("introduced", MAPPER.getNodeFactory().textNode(""))]], null, null))) | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"), arr(affectedEntry("g:n", [[obj().put("bogus", "1.0")]], null, null)))                           | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"),
                arr(entryWith([name: "g:n"], arr(MAPPER.getNodeFactory().textNode("x")), null)))                                                             | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"),
                arr(entryWith([name: "g:n"], arr(rangeOf(MAPPER.getNodeFactory().textNode("x"))), null)))                                                    | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"),
                arr(entryWith([name: "g:n"], arr(rangeOf(arr(MAPPER.getNodeFactory().textNode("x")))), null)))                                               | "GHSA-1"
        record(MAPPER.getNodeFactory().textNode("GHSA-1"),
                arr(entryWith([name: "g:n"], arr(rangeOf(arr(eventWith([introduced: MAPPER.getNodeFactory().numberNode(42)])))), null)))                  | "GHSA-1"
    }

    def "given aliases of mixed types when parsed then only non-empty text aliases are kept"() {
        given:
        def node = obj()
        node.put("id", "GHSA-2")
        node.set("aliases", arr(MAPPER.getNodeFactory().numberNode(42),
                MAPPER.getNodeFactory().textNode(""), MAPPER.getNodeFactory().textNode("CVE-X")))
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.aliases() == ["CVE-X"]
        record.summary() == ""
    }

    def "given a severity entry without a score when parsed then the type alone is kept"() {
        given:
        def node = obj()
        node.put("id", "GHSA-6")
        node.set("severity", arr(obj().put("type", "CVSS_V3")))
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.severities() == ["CVSS_V3"]
    }

    def "given severity entries of mixed types when parsed then only object entries with a non-empty type are kept"() {
        given:
        def node = obj()
        node.put("id", "GHSA-7")
        node.set("severity", arr(MAPPER.getNodeFactory().textNode("plain"),
                obj(),
                obj().put("type", ""),
                obj().put("type", "CVSS_V4").put("score", "CVSS:4.0/vector")))
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.severities() == ["CVSS_V4: CVSS:4.0/vector"]
    }

    def "given a record without a severity array but a top-level database_specific severity when parsed then the level is used"() {
        given:
        def node = obj()
        node.put("id", "GHSA-8")
        def db = obj()
        db.put("severity", "HIGH")
        node.set("database_specific", db)
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.severities() == ["HIGH"]
    }

    def "given a database_specific without a severity field when parsed then no severity is derived"() {
        given:
        def node = obj()
        node.put("id", "GHSA-9")
        def db = obj()
        db.put("cwe_ids", "CWE-20")
        node.set("database_specific", db)
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.severities().isEmpty()
    }

    def "given a database_specific with a non-text severity when parsed then no severity is derived"() {
        given:
        def node = obj()
        node.put("id", "GHSA-10")
        def db = obj()
        db.put("severity", MAPPER.getNodeFactory().numberNode(4))
        node.set("database_specific", db)
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.severities().isEmpty()
    }

    def "given a withdrawn field that is null when parsed then the record is not withdrawn"() {
        given:
        def node = obj()
        node.put("id", "GHSA-3")
        node.set("withdrawn", MAPPER.getNodeFactory().nullNode())
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.withdrawnAt() == null
        !record.withdrawn()
    }

    def "given a withdrawn field that is boolean true when parsed then the record is withdrawn"() {
        given:
        def node = obj()
        node.put("id", "GHSA-4")
        node.put("withdrawn", true)
        node.set("affected", arr(affectedEntry("g:n", null, ["1.0"], null)))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.withdrawnAt() == "true"
        record.withdrawn()
    }

    def "given a versions list of mixed types when parsed then only non-empty text versions are kept"() {
        given:
        def node = recordWithAffectedFull("g:n", [["introduced": "0"]], [42, "", "1.0"], null)

        when:
        def record = OsvRecord.parse(node)

        then:
        record.affected().get(0).versions() == ["1.0"]
    }

    def "given a database_specific field that is not an object when parsed then no hint is derived"() {
        given:
        def entry = obj()
        def pkg = obj()
        pkg.put("name", "g:n")
        entry.set("package", pkg)
        def ranges = MAPPER.createArrayNode()
        def range = obj()
        range.put("type", "ECOSYSTEM")
        def events = MAPPER.createArrayNode()
        events.add(obj().put("introduced", "0"))
        range.set("events", events)
        ranges.add(range)
        entry.set("ranges", ranges)
        entry.set("database_specific", MAPPER.getNodeFactory().textNode("x"))
        def node = obj()
        node.put("id", "GHSA-5")
        node.set("affected", arr(entry))

        when:
        def record = OsvRecord.parse(node)

        then:
        record.affected().get(0).ranges().get(0).events() == [new VersionEvent("introduced", "0")]
    }

    def "given a last_known_affected_version_range that is not text when parsed then no hint is derived"() {
        given:
        def node = recordWithAffectedFull("g:n", [["introduced": "0"]], null,
                [last_known_affected_version_range: MAPPER.getNodeFactory().numberNode(42)])

        when:
        def record = OsvRecord.parse(node)

        then:
        record.affected().get(0).ranges().get(0).events() == [new VersionEvent("introduced", "0")]
    }

    private static ObjectNode affectedEntry(String name, List eventsList, List versions, Map dbSpecific) {
        def entry = obj()
        if (name != null) {
            def pkg = obj()
            pkg.put("name", name)
            entry.set("package", pkg)
        }
        if (eventsList != null) {
            def ranges = MAPPER.createArrayNode()
            eventsList.each { evts ->
                def range = obj()
                range.put("type", "ECOSYSTEM")
                def events = MAPPER.createArrayNode()
                if (evts instanceof Map) {
                    evts.each { k, v -> events.add(obj().put(k as String, v as String)) }
                } else {
                    evts.each { ev -> events.add(ev as JsonNode) }
                }
                range.set("events", events)
                ranges.add(range)
            }
            entry.set("ranges", ranges)
        }
        if (versions != null) {
            entry.set("versions", arr(versions as Object[]))
        }
        if (dbSpecific != null) {
            def db = obj()
            dbSpecific.each { k, v -> db.put(k as String, v as String) }
            entry.set("database_specific", db)
        }
        return entry
    }

    private static ObjectNode recordWithAffected(String name, List eventsList, List versions, Map dbSpecific) {
        def node = obj()
        node.put("id", "GHSA-HINT")
        node.set("affected", arr(affectedEntry(name, eventsList, versions, dbSpecific)))
        return node
    }
}
