package org.reachability.analyzer.sbom

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path

/**
 * M7c: the SPDX 2.x JSON parser (A15). The committed spdx-mini fixture
 * mirrors bom-mini (stublib 1.0 via a purl external ref, plus a package
 * without a purl); the rest are the skip/warn edge cases — non-maven and
 * unparseable purls, missing names, empty ref values, empty packages —
 * and the SPDX-3.x rejection boundary.
 */
class SpdxJsonParserSpec extends Specification {

    private static final ObjectMapper MAPPER = new ObjectMapper()
    private static final SpdxJsonParser PARSER = new SpdxJsonParser()

    private static JsonNode root(String json) {
        MAPPER.readTree(json)
    }

    private static JsonNode fixtureRoot() {
        MAPPER.readTree(new String(Files.readAllBytes(
                Path.of("src/test/resources/fixtures/spdx-mini.json"))))
    }

    def "given the committed spdx-mini fixture when parsed then the maven package is a component and the no-purl package is a warning"() {
        given:
        JsonNode root = fixtureRoot()

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.format == "SPDX"
        parsed.specVersion == "SPDX-2.3"
        parsed.components.size() == 1
        def component = parsed.components[0]
        component.name == "stublib"
        component.version == "1.0"
        component.bomRef == "SPDXRef-stublib"
        component.purl.toString() == "pkg:maven/stublib/stublib@1.0"
        component.purl.isMaven()

        and: "the package without a purl is skipped with the same warning contract as CycloneDX"
        parsed.warnings.size() == 1
        parsed.warnings[0].contains("no-purl-lib")
        parsed.warnings[0].contains("no purl")
    }

    def "given spdx 2.x documents when canParse is asked then only the SPDX-2 prefixed versions match"() {
        expect:
        PARSER.canParse(root('{"spdxVersion": "' + version + '", "name": "x"}')) == expected

        where:
        version      | expected
        "SPDX-2.0"   | true
        "SPDX-2.3"   | true
        "SPDX-3.0.1" | false
        "3.0.0"      | false
        "2.3"        | false
        ""           | false
    }

    def "given a cyclonedx document when canParse is asked then false"() {
        expect:
        !PARSER.canParse(root('{"bomFormat": "CycloneDX", "specVersion": "1.6"}'))
    }

    def "given a package without a name when parsed then it is skipped with a warning"() {
        given:
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": [ ' +
                '{"SPDXRef-id": "SPDXRef-a", "versionInfo": "1.0", "externalRefs": ' +
                '[{"referenceType": "purl", "reference": "pkg:maven/g/h@1.0"}] } ]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.size() == 1
        parsed.warnings[0].contains("without a name")
    }

    def "given a package with a non-maven purl when parsed then it is skipped with a warning"() {
        given:
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": [ ' +
                '{"name": "npm-lib", "versionInfo": "1.0", "externalRefs": ' +
                '[{"referenceType": "purl", "reference": "pkg:npm/node_modules/npm-lib@1.0"}] } ]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.size() == 1
        parsed.warnings[0].contains("not a maven purl")
    }

    def "given a package with an unparseable purl when parsed then it is skipped with a warning"() {
        given:
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": [ ' +
                '{"name": "broken", "versionInfo": "1.0", "externalRefs": ' +
                '[{"referenceType": "purl", "reference": "not a purl at all"}] } ]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.size() == 1
        parsed.warnings[0].contains("unparseable purl")
    }

    def "given a package with several external refs when parsed then the purl-typed ref wins"() {
        given: "a cpe23 ref before the purl ref"
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": [ ' +
                '{"name": "multi-ref", "versionInfo": "2.0", "externalRefs": [ ' +
                '{"referenceCategory": "SECURITY-TACK", "referenceType": "cpe23", "reference": "cpe:2.3:a/multi/ref/2.0"}, ' +
                '{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "reference": "pkg:maven/multi/ref@2.0"} ] } ]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.size() == 1
        parsed.components[0].purl.toString() == "pkg:maven/multi/ref@2.0"
    }

    def "given a package whose purl ref is an empty string when parsed then it is treated as no purl"() {
        given:
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": [ ' +
                '{"name": "empty-ref", "versionInfo": "1.0", "externalRefs": ' +
                '[{"referenceType": "purl", "reference": ""}] } ]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.size() == 1
        parsed.warnings[0].contains("no purl")
    }

    def "given a package without a version when parsed then the component version is null"() {
        given:
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": [ ' +
                '{"name": "no-version", "externalRefs": ' +
                '[{"referenceType": "purl", "reference": "pkg:maven/g/h"}] } ]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.size() == 1
        parsed.components[0].version == null
        parsed.components[0].bomRef == null
    }

    def "given a document with an empty packages array when parsed then zero components and no warnings"() {
        given:
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "packages": []}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.isEmpty()
    }

    def "given a document without a packages field when parsed then zero components and no warnings"() {
        given: "an SPDX document describing only files"
        JsonNode root = root('{"spdxVersion": "SPDX-2.3", "files": [{"fileName": "a.txt"}]}')

        when:
        ParsedSbom parsed = PARSER.parse(root)

        then:
        parsed.components.isEmpty()
        parsed.warnings.isEmpty()
    }
}
