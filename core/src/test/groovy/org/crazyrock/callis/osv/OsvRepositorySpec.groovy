package org.crazyrock.callis.osv

import org.crazyrock.callis.sbom.Purl
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * Unit tests for the OSV repository (M2 T21/T21b): dual name-form indexing
 * (raw "group:artifact" and purl "group/artifact"), withdrawn records never
 * indexed, malformed records warned + skipped + counted, and the fail-safe
 * counts for a corrupted snapshot.
 */
class OsvRepositorySpec extends Specification {

    private static final String FIXTURE_DIR = "src/test/resources/fixtures/osv"

    @TempDir
    Path workDir

    private Path copyFixtures() {
        def fixtureDir = Path.of(FIXTURE_DIR)
        Files.list(fixtureDir).filter { it.toFile().name.endsWith(".json") }.forEach {
            Files.copy(it, workDir.resolve(it.toFile().name))
        }
        return workDir
    }

    def "given the five real fixture records when scanned then all are indexed except the withdrawn one"() {
        given:
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.fileCount() == 5
        repo.malformedCount() == 0
        repo.withdrawnCount() == 1
        repo.validRecordCount() == 5
        repo.indexedRecordCount() == 4
        repo.warnings().isEmpty()
    }

    def "given a log4j-core purl when looked up in both name forms then the same record is found"() {
        given:
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.lookup(Purl.parse("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")).any { it.id() == "GHSA-jfh8-c2jp-5v3q" }
        repo.lookup(Purl.parse("pkg:maven/org.apache.logging.log4j/log4j-core")).any { it.id() == "GHSA-jfh8-c2jp-5v3q" }
    }

    def "given a plain-name purl without namespace when looked up then the plain-name record is found"() {
        given:
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.lookup(Purl.parse("pkg:maven//executorch")).any { it.id() == "GHSA-xc7w-r669-48pf" }
    }

    def "given a namespaced purl whose artifact name equals a plain-name entry in a record when looked up then no record is returned"() {
        given: "the executorch record carries a group-less 'executorch' entry; a group-qualified purl must not match it"
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.lookup(Purl.parse("pkg:maven/org.pytorch/executorch")).isEmpty()
    }

    def "given a group-qualified purl matching an entry of a multi-name record when looked up then the record is found"() {
        given:
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.lookup(Purl.parse("pkg:maven/org.pytorch/executorch-android@0.6.0")).any { it.id() == "GHSA-xc7w-r669-48pf" }
    }

    def "given an unknown purl when looked up then no records"() {
        given:
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.lookup(Purl.parse("pkg:maven/unknown/unknown@1.0")).isEmpty()
    }

    def "given a record indexed under both name forms when queried per key then both keys resolve"() {
        given:
        def repo = new OsvRepository(copyFixtures())

        expect:
        repo.recordsNamed("org.apache.logging.log4j:log4j-core").any { it.id() == "GHSA-jfh8-c2jp-5v3q" }
        repo.recordsNamed("org.apache.logging.log4j/log4j-core").any { it.id() == "GHSA-jfh8-c2jp-5v3q" }
    }

    def "given a malformed file next to valid records when scanned then it is skipped with a warning and a count"() {
        given:
        copyFixtures()
        Files.write(workDir.resolve("corrupt.json"), "not a json record".bytes)

        when:
        def repo = new OsvRepository(workDir)

        then:
        repo.fileCount() == 6
        repo.malformedCount() == 1
        repo.validRecordCount() == 5
        repo.warnings().size() == 1
        repo.warnings()[0].contains("corrupt.json")
    }

    def "given a directory where every record is malformed when scanned then counts expose the corruption"() {
        given:
        Files.write(workDir.resolve("corrupt.json"), "not a json record".bytes)

        when:
        def repo = new OsvRepository(workDir)

        then:
        repo.fileCount() == 1
        repo.validRecordCount() == 0
        repo.indexedRecordCount() == 0
        repo.malformedCount() == 1
    }

    def "given an empty directory when scanned then all counts are zero"() {
        when:
        def repo = new OsvRepository(workDir)

        then:
        repo.fileCount() == 0
        repo.validRecordCount() == 0
        repo.warnings().isEmpty()
    }

    def "given non-json files when scanned then they are ignored"() {
        given:
        Files.write(workDir.resolve("README.md"), "ignore me".bytes)

        when:
        def repo = new OsvRepository(workDir)

        then:
        repo.fileCount() == 0
    }

    def "given a zero-byte json file next to valid records when scanned then it is skipped with an empty-file warning"() {
        given:
        copyFixtures()
        Files.write(workDir.resolve("empty.json"), new byte[0])

        when:
        def repo = new OsvRepository(workDir)

        then:
        repo.fileCount() == 6
        repo.malformedCount() == 1
        repo.warnings().any { it.contains("empty.json") && it.contains("empty file") }
    }

    def "given a json file containing the null literal when scanned then it is skipped with a null-file warning"() {
        given:
        copyFixtures()
        Files.write(workDir.resolve("null.json"), "null".bytes)

        when:
        def repo = new OsvRepository(workDir)

        then:
        repo.malformedCount() == 1
        repo.warnings().any { it.contains("null.json") && it.contains("JSON null") }
    }

    def "given a non-existent directory when constructed then IOException naming the path"() {
        when:
        new OsvRepository(workDir.resolve("no-such-dir"))

        then:
        def e = thrown(IOException)
        e.message.contains("no-such-dir")
    }

    def "given a record with duplicated entries for one name when indexed then the record appears once per key"() {
        given: "the log4shell record lists org.apache.logging.log4j:log4j-core in three entries"
        def repo = new OsvRepository(copyFixtures())

        when:
        def records = repo.recordsNamed("org.apache.logging.log4j:log4j-core")

        then:
        records.count { it.id() == "GHSA-jfh8-c2jp-5v3q" } == 1
    }
}
