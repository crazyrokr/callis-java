package org.reachability.analyzer.sbom

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import spock.lang.Specification

/**
 * CycloneDX parsing (M1 T13). The fixture bom.json is a real artifact:
 * generated once via `mvn package` with cyclonedx-maven-plugin 2.9.1 on a
 * project depending on log4j-core 2.14.1 + commons-lang3 3.14.0
 * (sha256 5826a2cc8ff2690ffe1af54ace05d4d6e69bdb8dc1fcbba85c4a6fa53b3e988a).
 */
class CycloneDxParserSpec extends Specification {

    private static final ObjectMapper MAPPER = new ObjectMapper()

    private static JsonNode readFixture(String name) {
        MAPPER.readTree(new File("src/test/resources/fixtures/" + name))
    }

    def "given real bom.json fixture when parsed then all maven components are found"() {
        given:
        JsonNode root = readFixture("bom.json")
        CycloneDxParser parser = new CycloneDxParser()

        when:
        ParsedSbom parsed = parser.parse(root)

        then: "the fixture carries the log4j and commons-lang3 components"
        parsed.format == "CycloneDX"
        parsed.specVersion == "1.6"
        parsed.warnings.isEmpty()
        parsed.components.size() == 3

        and:
        def log4j = parsed.components.find { it.name == "log4j-core" }
        log4j.version == "2.14.1"
        log4j.purl.isMaven()
        log4j.purl.namespace == "org.apache.logging.log4j"
        log4j.purl.name == "log4j-core"
        log4j.purl.version == "2.14.1"

        and:
        def lang3 = parsed.components.find { it.name == "commons-lang3" }
        lang3.version == "3.14.0"
        lang3.purl.qualifiedName == "org.apache.commons:commons-lang3"
    }

    def "given bomFormat CycloneDX when canParse then true"() {
        expect:
        new CycloneDxParser().canParse(root) == expected

        where:
        root                                              | expected
        MAPPER.readTree('{"bomFormat": "CycloneDX"}')     | true
        MAPPER.readTree('{"bomFormat": "cyclonedx"}')     | true
        MAPPER.readTree('{"spdxVersion": "SPDX-2.3"}')    | false
        MAPPER.readTree('{}')                             | false
        MAPPER.readTree('[1, 2]')                         | false
    }

    def "given components without purl when parsed then skipped with warning"() {
        given:
        JsonNode root = MAPPER.readTree('''
            {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [
               {"name": "no-purl", "version": "1.0"},
               {"name": "with-purl", "version": "2.0", "purl": "pkg:maven/g/with-purl@2.0"}
             ]}
        ''')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.size() == 1
        parsed.components[0].name == "with-purl"
        parsed.warnings.any { it.contains("no-purl") }
    }

    def "given component without version when parsed then version is null"() {
        given:
        JsonNode root = MAPPER.readTree('''
            {"bomFormat": "CycloneDX", "specVersion": "1.5",
             "components": [
               {"name": "nover", "purl": "pkg:maven/g/nover"}
             ]}
        ''')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.size() == 1
        parsed.components[0].version == null
        parsed.components[0].purl.version == null
    }

    def "given nested components when parsed then all levels are collected"() {
        given:
        JsonNode root = MAPPER.readTree('''
            {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [
               {"name": "outer", "version": "1.0", "purl": "pkg:maven/g/outer@1.0",
                "components": [
                  {"name": "inner", "version": "2.0", "purl": "pkg:maven/g/inner@2.0"}
                ]}
             ]}
        ''')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.size() == 2
        parsed.components*.name.containsAll(["outer", "inner"])
    }

    def "given unsupported spec version when parsed then SbomFormatException"() {
        given:
        JsonNode root = MAPPER.readTree('{"bomFormat": "CycloneDX", "specVersion": "9.9", "components": []}')

        when:
        new CycloneDxParser().parse(root)

        then:
        def e = thrown(SbomFormatException)
        e.message.contains("9.9")
    }

    def "given missing spec version when parsed then parsed with warning"() {
        given:
        JsonNode root = MAPPER.readTree('{"bomFormat": "CycloneDX", "components": []}')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.specVersion == null
        parsed.components.isEmpty()
        parsed.warnings.any { it.contains("specVersion") }
    }

    def "given non-maven purl component when parsed then skipped with warning"() {
        given:
        JsonNode root = MAPPER.readTree('''
            {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [
               {"name": "py-dep", "version": "1.0", "purl": "pkg:pypi/py-dep@1.0"}
             ]}
        ''')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.any { it.contains("py-dep") }
    }

    def "given unparseable purl when parsed then component skipped with warning"() {
        given:
        JsonNode root = MAPPER.readTree('''
            {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [
               {"name": "bad-purl", "version": "1.0", "purl": "not-a-purl"}
             ]}
        ''')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.any { it.contains("bad-purl") }
    }

    def "given no components node when parsed then zero components, no error"() {
        given:
        JsonNode root = MAPPER.readTree('{"bomFormat": "CycloneDX", "specVersion": "1.6"}')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.isEmpty()
    }

    def "given component without name when parsed then skipped with warning"() {
        given:
        JsonNode root = MAPPER.readTree('''
            {"bomFormat": "CycloneDX", "specVersion": "1.6",
             "components": [
               {"version": "1.0", "purl": "pkg:maven/g/anonymous@1.0"}
             ]}
        ''')

        when:
        ParsedSbom parsed = new CycloneDxParser().parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.any { it.contains("without a name") }
    }
}
