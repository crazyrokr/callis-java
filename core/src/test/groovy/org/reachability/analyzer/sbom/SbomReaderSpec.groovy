package org.reachability.analyzer.sbom

import spock.lang.Specification

/** Format auto-detection (A15): CycloneDX now, SPDX deferred to M7. */
class SbomReaderSpec extends Specification {

    private static File writeTemp(String name, String content) {
        def file = File.createTempFile("sbom", ".json", new File("build"))
        file.text = content
        file.deleteOnExit()
        return file
    }

    def "given cyclonedx bom.json when read then parsed"() {
        given:
        File file = new File("src/test/resources/fixtures/bom.json")

        when:
        ParsedSbom parsed = SbomReader.parse(file.toPath())

        then:
        parsed.format == "CycloneDX"
        parsed.components.size() == 3
    }

    def "given spdx document when read then explicit error mentioning SPDX"() {
        given:
        File file = writeTemp("spdx", '{"spdxVersion": "SPDX-2.3", "name": "x"}')

        when:
        SbomReader.parse(file.toPath())

        then:
        def e = thrown(SbomFormatException)
        e.message.contains("SPDX")
    }

    def "given unknown bomFormat when read then explicit error with the value"() {
        given:
        File file = writeTemp("weird", '{"bomFormat": "SomeOtherFormat"}')

        when:
        SbomReader.parse(file.toPath())

        then:
        def e = thrown(SbomFormatException)
        e.message.contains("SomeOtherFormat")
    }

    def "given document with neither marker when read then explicit error"() {
        given:
        File file = writeTemp("empty", '{"name": "x"}')

        when:
        SbomReader.parse(file.toPath())

        then:
        def e = thrown(SbomFormatException)
        e.message.contains("neither bomFormat")
    }

    def "given non-object json when read then explicit error"() {
        given:
        File file = writeTemp("array", '[1, 2, 3]')

        when:
        SbomReader.parse(file.toPath())

        then:
        thrown(SbomFormatException)
    }

    def "given unsupported spec version when read then explicit error"() {
        given:
        File file = writeTemp("newspec", '{"bomFormat": "CycloneDX", "specVersion": "9.9", "components": []}')

        when:
        SbomReader.parse(file.toPath())

        then:
        def e = thrown(SbomFormatException)
        e.message.contains("9.9")
    }
}
