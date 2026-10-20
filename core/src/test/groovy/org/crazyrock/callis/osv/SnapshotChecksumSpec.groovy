package org.crazyrock.callis.osv

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest

/**
 * Unit tests for the OSV snapshot checksum (A14 pinning): deterministic over
 * the directory content, independent of file creation order, and stable across
 * snapshots so a mismatched --osv-checksum fails the run.
 */
class SnapshotChecksumSpec extends Specification {

    @TempDir
    Path workDir

    private static String emptyDirectoryHash() {
        MessageDigest.getInstance("SHA-256")
                .digest(new byte[0])
                .collect { String.format("%02x", it) }
                .join()
    }

    def "given two directories with identical json content when hashed then the hashes are equal"() {
        given:
        def a = workDir.resolve("a")
        def b = workDir.resolve("b")
        Files.createDirectories(a)
        Files.createDirectories(b)
        [a, b].each { dir ->
            Files.write(dir.resolve("zeta.json"), "second".bytes)
            Files.write(dir.resolve("alpha.json"), "first".bytes)
        }

        expect:
        SnapshotChecksum.sha256OfDirectory(a) == SnapshotChecksum.sha256OfDirectory(b)
    }

    def "given a changed file content when rehashed then the hash changes"() {
        given:
        def dir = workDir.resolve("c")
        Files.createDirectories(dir)
        Files.write(dir.resolve("r.json"), "one".bytes)
        def before = SnapshotChecksum.sha256OfDirectory(dir)

        when:
        Files.write(dir.resolve("r.json"), "two".bytes)

        then:
        SnapshotChecksum.sha256OfDirectory(dir) != before
    }

    def "given a non-json file added when rehashed then the hash is unchanged"() {
        given:
        def dir = workDir.resolve("d")
        Files.createDirectories(dir)
        Files.write(dir.resolve("r.json"), "one".bytes)
        def before = SnapshotChecksum.sha256OfDirectory(dir)

        when:
        Files.write(dir.resolve("notes.txt"), "ignored".bytes)

        then:
        SnapshotChecksum.sha256OfDirectory(dir) == before
    }

    def "given an empty directory when hashed then the sha256 of empty input"() {
        given:
        def dir = workDir.resolve("empty")
        Files.createDirectories(dir)

        expect:
        SnapshotChecksum.sha256OfDirectory(dir) == emptyDirectoryHash()
    }

    def "given a non-directory path when hashed then IOException"() {
        given:
        def file = workDir.resolve("plain.json")
        Files.write(file, "x".bytes)

        when:
        SnapshotChecksum.sha256OfDirectory(file)

        then:
        thrown(IOException)
    }

    def "given a single record file when hashed then the hash covers name and content"() {
        given:
        def dir = workDir.resolve("e")
        Files.createDirectories(dir)
        Files.write(dir.resolve("r.json"), "x".bytes)
        def fileHex = MessageDigest.getInstance("SHA-256")
                .digest("x".bytes)
                .collect { String.format("%02x", it) }
                .join()
        def expectedContentHash = MessageDigest.getInstance("SHA-256")
                .digest(("r.json:" + fileHex + "\n").bytes)
                .collect { String.format("%02x", it) }
                .join()

        expect:
        SnapshotChecksum.sha256OfDirectory(dir) == expectedContentHash
    }
}
