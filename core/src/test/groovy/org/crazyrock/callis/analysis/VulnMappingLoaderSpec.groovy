package org.crazyrock.callis.analysis

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T42 vuln-mappings tests (M4): strict parsing of the mapping file —
 * object root, required class/method per entry, optional descriptor,
 * and malformed shapes rejected before any analysis runs (exit 2 upstream).
 */
class VulnMappingLoaderSpec extends Specification {

    private static final File VALID = new File("src/test/resources/fixtures/mappings/valid.json")
    private static final File MALFORMED_ROOT = new File("src/test/resources/fixtures/mappings/malformed.json")
    private static final File MALFORMED_ENTRY = new File("src/test/resources/fixtures/mappings/malformed-entry.json")

    @TempDir
    Path workDir

    def "given the valid fixture mapping when loaded then all ids parse with the descriptor left optional"() {
        when:
        Map<String, List<VulnMappingLoader.VulnTarget>> loaded = new VulnMappingLoader().load(VALID.toPath())

        then:
        loaded.keySet() == ["VULN-POS", "VULN-NEG", "VULN-NOCLASS", "VULN-DESC"] as Set
        loaded["VULN-POS"] == [new VulnMappingLoader.VulnTarget("stublib.Stub", "danger", null)]
        loaded["VULN-NEG"] == [new VulnMappingLoader.VulnTarget("stublib.Stub", "safe", null)]
        loaded["VULN-DESC"] == [new VulnMappingLoader.VulnTarget("stublib.Stub", "danger", "()")]
        loaded["VULN-NOCLASS"] == [new VulnMappingLoader.VulnTarget("nope.Gone", "gone", null)]
    }

    def "given a mapping file whose root is an array when loaded then a format exception names the file"() {
        when:
        new VulnMappingLoader().load(MALFORMED_ROOT.toPath())

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains(MALFORMED_ROOT.name)
        e.message.contains("object")
    }

    def "given a mapping entry without a class when loaded then a format exception names the id and field"() {
        when:
        new VulnMappingLoader().load(MALFORMED_ENTRY.toPath())

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("VULN-POS")
        e.message.contains("class")
    }

    def "given a mapping file that does not exist when loaded then an IOException"() {
        when:
        new VulnMappingLoader().load(workDir.resolve("missing.json"))

        then:
        thrown(IOException)
    }

    def "given an empty object when loaded then an empty mapping is returned"() {
        given:
        def file = workDir.resolve("empty.json")
        Files.write(file, '{}'.bytes)

        when:
        Map<String, List<VulnMappingLoader.VulnTarget>> loaded = new VulnMappingLoader().load(file)

        then:
        loaded.isEmpty()
    }

    def "given an entry that is not an object when loaded then a format exception"() {
        given:
        def file = workDir.resolve("string-entry.json")
        Files.write(file, '{"VULN-POS": ["stublib.Stub"]}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("VULN-POS")
        e.message.contains("object")
    }

    def "given an entry with a non-textual class when loaded then a format exception"() {
        given:
        def file = workDir.resolve("number-class.json")
        Files.write(file, '{"VULN-POS": [{"class": 42, "method": "danger"}]}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("class")
    }

    def "given a null descriptor when loaded then it is normalized to absent"() {
        given:
        def file = workDir.resolve("null-descriptor.json")
        Files.write(file, '{"VULN-POS": [{"class": "stublib.Stub", "method": "danger", "descriptor": null}]}'.bytes)

        when:
        Map<String, List<VulnMappingLoader.VulnTarget>> loaded = new VulnMappingLoader().load(file)

        then:
        loaded["VULN-POS"][0].descriptor() == null
    }

    def "given an empty file when loaded then a format exception is thrown"() {
        given:
        def file = workDir.resolve("zero-bytes.json")
        Files.write(file, new byte[0])

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("object")
    }

    def "given a null field value when loaded then a format exception names the id"() {
        given:
        def file = workDir.resolve("null-value.json")
        Files.write(file, '{"VULN-POS": null}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("VULN-POS")
        e.message.contains("list")
    }

    def "given a scalar field value when loaded then a format exception names the id"() {
        given:
        def file = workDir.resolve("scalar-value.json")
        Files.write(file, '{"VULN-POS": "stublib.Stub"}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("VULN-POS")
        e.message.contains("list")
    }

    def "given a null entry when loaded then a format exception names the id"() {
        given:
        def file = workDir.resolve("null-entry.json")
        Files.write(file, '{"VULN-POS": [null]}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("VULN-POS")
        e.message.contains("object")
    }

    def "given an empty class name when loaded then a format exception names the field"() {
        given:
        def file = workDir.resolve("empty-class.json")
        Files.write(file, '{"VULN-POS": [{"class": "", "method": "danger"}]}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("class")
    }

    def "given an entry without a method when loaded then a format exception names the field"() {
        given:
        def file = workDir.resolve("no-method.json")
        Files.write(file, '{"VULN-POS": [{"class": "stublib.Stub"}]}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("method")
    }

    def "given an empty method name when loaded then a format exception names the field"() {
        given:
        def file = workDir.resolve("empty-method.json")
        Files.write(file, '{"VULN-POS": [{"class": "stublib.Stub", "method": ""}]}'.bytes)

        when:
        new VulnMappingLoader().load(file)

        then:
        def e = thrown(VulnMappingFormatException)
        e.message.contains("method")
    }

    def "given a blank descriptor when loaded then it is normalized to absent"() {
        given:
        def file = workDir.resolve("blank-descriptor.json")
        Files.write(file, '{"VULN-POS": [{"class": "stublib.Stub", "method": "danger", "descriptor": "   "}]}'.bytes)

        when:
        Map<String, List<VulnMappingLoader.VulnTarget>> loaded = new VulnMappingLoader().load(file)

        then:
        loaded["VULN-POS"][0].descriptor() == null
    }
}
