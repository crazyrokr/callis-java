package org.reachability.analyzer.analysis

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * A12 guard tests (T31, M3): the guard must turn SootUp's silent zero-class
 * behavior (verified in BytecodeCeilingSpec) into a loud exit-3 failure before
 * any analysis runs.
 */
class BytecodeVersionGuardSpec extends Specification {

    private static final File BYTECODE_FIXTURES = new File("src/test/resources/fixtures/bytecode")

    @TempDir
    Path workDir

    def "given release-25 classes when scanned then the ceiling is exactly at 69 and nothing is above it"() {
        given:
        def scan = BytecodeVersionGuard.scan(new File(BYTECODE_FIXTURES, "v69").toPath())

        expect:
        scan.classFiles().size() == 1
        scan.maxMajor() == 69
        scan.aboveCeiling().isEmpty()
    }

    def "given a class file at major 70 when scanned then it is above the ceiling"() {
        given:
        def scan = BytecodeVersionGuard.scan(new File(BYTECODE_FIXTURES, "v70").toPath())

        expect:
        scan.classFiles().size() == 1
        scan.maxMajor() == 70
        scan.aboveCeiling().size() == 1
    }

    def "given a directory without class files when scanned then the scan is empty"() {
        given:
        Files.write(workDir.resolve("notes.txt"), "not a class file".bytes)

        when:
        def scan = BytecodeVersionGuard.scan(workDir)

        then:
        scan.classFiles().isEmpty()
        scan.maxMajor() == 0
        scan.aboveCeiling().isEmpty()
    }

    def "given a non-existent directory when scanned then the scan is empty"() {
        expect:
        def scan = BytecodeVersionGuard.scan(workDir.resolve("no-such-dir"))
        scan.classFiles().isEmpty() && scan.maxMajor() == 0 && scan.aboveCeiling().isEmpty()
    }

    def "given classes at or below the ceiling when checked then no exception"() {
        given:
        def scan = BytecodeVersionGuard.scan(new File(BYTECODE_FIXTURES, "v69").toPath())

        when:
        BytecodeVersionGuard.requireSupported(scan, null)

        then: "69 == ceiling passes; the hint is optional"
        notThrown(AnalysisException)
    }

    def "given a class above the ceiling when checked then AnalysisException with the ceiling and the file"() {
        given:
        def scan = BytecodeVersionGuard.scan(new File(BYTECODE_FIXTURES, "v70").toPath())

        when:
        BytecodeVersionGuard.requireSupported(scan, null)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("ceiling")
        e.message.contains("69")
        e.message.contains("TooNewProbe.class")
    }

    def "given a class above the ceiling and an expected java version when checked then the hint is included"() {
        given:
        def scan = BytecodeVersionGuard.scan(new File(BYTECODE_FIXTURES, "v70").toPath())

        when:
        BytecodeVersionGuard.requireSupported(scan, 26)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("expected Java 26")
    }

    def "given six classes above the ceiling when checked then the message truncates the file list"() {
        given:
        (1..6).each { i ->
            Files.copy(new File(BYTECODE_FIXTURES, "v70/TooNewProbe.class").toPath(),
                    workDir.resolve("Bad" + i + ".class"))
        }
        def scan = BytecodeVersionGuard.scan(workDir)

        when:
        BytecodeVersionGuard.requireSupported(scan, null)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("and 1 more")
    }

    def "given real fixture files when read then the major versions match the file format"() {
        expect:
        BytecodeVersionGuard.classFileMajorVersion(new File(BYTECODE_FIXTURES, "v69/Release25Probe.class").toPath()) == 69
        BytecodeVersionGuard.classFileMajorVersion(new File(BYTECODE_FIXTURES, "v70/TooNewProbe.class").toPath()) == 70
    }

    def "given a directory without read permission when scanned then AnalysisException (cannot scan)"() {
        given:
        def locked = workDir.resolve("locked")
        Files.createDirectory(locked)
        TestPermissions.withoutRead(locked)

        when:
        BytecodeVersionGuard.scan(locked)

        then:
        def e = thrown(AnalysisException)
        e.message.contains("cannot scan")

        cleanup:
        TestPermissions.ownerReadWriteExecute(locked)
    }

    def "given a truncated or corrupt file when read then major is zero"() {
        given:
        Files.write(workDir.resolve(name), bytes)

        expect:
        BytecodeVersionGuard.classFileMajorVersion(workDir.resolve(name)) == 0

        where:
        name              | bytes
        "truncated.class" | [0xCA, 0xFE, 0xBA, 0xBE] as byte[]
        "bad-magic.class" | ([0x00] * 10) as byte[]
    }

    def "given a non-existent file when read then major is zero"() {
        expect:
        BytecodeVersionGuard.classFileMajorVersion(workDir.resolve("missing.class")) == 0
    }
}
