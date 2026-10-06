package org.reachability.coveragetool

import org.jacoco.core.data.ExecutionDataStore
import org.reachability.coveragetool.CoverageGate.Gate
import org.reachability.coveragetool.CoverageGate.Parsed
import spock.lang.Specification

import java.nio.file.Files
import java.nio.file.Path

/**
 * Unit tests for the coverage gate (replaces the Gradle verification task,
 * ADR 0001 amendment). The "real data" tests need the execution data of the
 * main test task, so this spec runs after it (see build.gradle.kts).
 */
class CoverageGateSpec extends Specification {

    static final Path EXEC_FILE = Path.of("build/jacoco/test.exec")
    static final Path CLASSES_DIR = Path.of("build/classes/java/main")
    static final String SBOM = "org.reachability.analyzer.sbom"

    static ExecutionDataStore realStore() {
        CoverageGate.loadExecutionData(EXEC_FILE)
    }

    static List<Path> classDirs() {
        [CLASSES_DIR]
    }

    static int coveredFromReport(String report, String pkg, String counter) {
        def m = report =~ /(?m)^.{0,40}$pkg\s+$counter (\d+)\/(\d+)/
        assert m.find()
        Integer.parseInt(m.group(1))
    }

    static double ratioFromReport(String report, String pkg, String counter) {
        def m = report =~ /(?m)^.{0,40}$pkg\s+$counter \d+\/\d+ = ([\d.]+)/
        assert m.find()
        Double.parseDouble(m.group(1))
    }

    def "given real execution data when evaluated with min 0 then gate passes and some lines are covered"() {
        given: "the sbom package is covered by the real test run"
        def store = realStore()
        def gate = new Gate(SBOM, "LINE", 0.0)

        when:
        def result = CoverageGate.evaluate(store, classDirs(), [gate])

        then: "it passes and the report proves data actually flowed through (not vacuous)"
        result.exitCode == 0
        coveredFromReport(result.report, SBOM, "LINE") > 0
        !result.report.contains("VIOLATION")
    }

    def "given real execution data when the min is the measured ratio then the gate is self-consistent"() {
        given: "measuring the current ratio from the same data"
        def store = realStore()
        def baseline = CoverageGate.evaluate(store, classDirs(), [new Gate(SBOM, "LINE", 0.0)])
        double ratio = ratioFromReport(baseline.report, SBOM, "LINE")

        expect: "it passes at the measured ratio"
        CoverageGate.evaluate(store, classDirs(), [new Gate(SBOM, "LINE", ratio)]).exitCode == 0

        and: "when below 100%, it fails just above the measured ratio"
        (ratio >= 1.0) || {
            def above = CoverageGate.evaluate(store, classDirs(),
                    [new Gate(SBOM, "LINE", Math.min(1.0, ratio + 0.01))])
            above.exitCode == 1 && above.report.contains("VIOLATION")
        }()
    }

    def "given execution data without any coverage when gated at 1.0 then the gate fails with zero ratio"() {
        given: "a valid exec file with no blocks (no session, no data)"
        def empty = Path.of("build/tmp/coveragetool-test/empty.exec")
        Files.createDirectories(empty.parent)
        Files.write(empty, new byte[0])
        def store = CoverageGate.loadExecutionData(empty)
        def gate = new Gate(SBOM, "LINE", 1.0)

        when:
        def result = CoverageGate.evaluate(store, classDirs(), [gate])

        then: "every line is missed, so a 100% gate must fail (false-positive guard)"
        result.exitCode == 1
        coveredFromReport(result.report, SBOM, "LINE") == 0
        result.report.contains("0.0000")
        result.report.contains("VIOLATION")
    }

    def "given execution data without any coverage when gated at 0.0 then the gate passes"() {
        given:
        def empty = Path.of("build/tmp/coveragetool-test/empty.exec")
        Files.createDirectories(empty.parent)
        Files.write(empty, new byte[0])
        def store = CoverageGate.loadExecutionData(empty)

        when:
        def result = CoverageGate.evaluate(store, classDirs(), [new Gate(SBOM, "LINE", 0.0)])

        then:
        result.exitCode == 0
    }

    def "given empty data when a BRANCH gate is used then branch counters are evaluated"() {
        given:
        def empty = Path.of("build/tmp/coveragetool-test/empty.exec")
        Files.createDirectories(empty.parent)
        Files.write(empty, new byte[0])
        def store = CoverageGate.loadExecutionData(empty)

        when: "gating the branch counter at 1.0"
        def result = CoverageGate.evaluate(store, classDirs(), [new Gate(SBOM, "BRANCH", 1.0)])

        then: "sbom classes contain branches, so the ratio is 0 and the gate fails"
        result.exitCode == 1
        result.report.contains("BRANCH")
        result.report.contains("VIOLATION")
    }

    def "given a package without main classes when gated then it is skipped and passes"() {
        given:
        def store = realStore()
        def gate = new Gate("org.reachability.analyzer.doesnotexist", "LINE", 1.0)

        when:
        def result = CoverageGate.evaluate(store, classDirs(), [gate])

        then:
        result.exitCode == 0
        result.report.contains("doesnotexist")
        result.report.contains("skipped")
    }

    def "given multiple gates when one violates then exit code is 1"() {
        given:
        def empty = Path.of("build/tmp/coveragetool-test/empty.exec")
        Files.createDirectories(empty.parent)
        Files.write(empty, new byte[0])
        def store = CoverageGate.loadExecutionData(empty)

        when:
        def result = CoverageGate.evaluate(store, classDirs(),
                [new Gate(SBOM, "LINE", 0.0), new Gate(SBOM, "LINE", 1.0)])

        then:
        result.exitCode == 1
    }

    def "given a malformed gate spec when parsed then IllegalArgumentException"() {
        when:
        CoverageGate.parseGate(spec)

        then:
        thrown(IllegalArgumentException)

        where:
        spec << [
                "org.pkg",
                "org.pkg:LINE",
                "org.pkg:LINE:x",
                "org.pkg:INSTR:0.5",
                "org.pkg:LINE:1.5",
                "org.pkg:LINE:-0.1",
                ":LINE:0.5"
        ]
    }

    def "given missing required options when parsed then IllegalArgumentException"() {
        when:
        CoverageGate.parse(args as String[])

        then:
        thrown(IllegalArgumentException)

        where:
        args << [
                [],
                ["--exec", "x.exec"],
                ["--classes", CLASSES_DIR.toString()],
                ["--exec", "x.exec", "--classes", CLASSES_DIR.toString()],
                ["--unknown", "x"]
        ]
    }

    def "given a well formed gate when parsed then fields are set"() {
        when:
        def gate = CoverageGate.parseGate("org.a.b:BRANCH:0.9")

        then:
        gate.packageName == "org.a.b"
        gate.counter == "BRANCH"
        Math.abs(gate.minimum - 0.9) < 1e-9
    }

    def "given a non existent exec file when loaded then IOException naming the file"() {
        when:
        CoverageGate.loadExecutionData(Path.of("build/tmp/no-such-exec.exec"))

        then:
        def e = thrown(IOException)
        e.message.contains("no-such-exec.exec")
    }

    def "given real data and a passing gate when run through the exit codes then 0"() {
        when:
        int code = CoverageGate.exitCode((["--exec", EXEC_FILE.toString(),
                                          "--classes", CLASSES_DIR.toString(),
                                          "--gate", "$SBOM:LINE:0.0"]) as String[])

        then:
        code == 0
    }

    def "given real data and a failing gate when run through the exit codes then 1"() {
        given: "measuring the current ratio first"
        def store = realStore()
        def baseline = CoverageGate.evaluate(store, classDirs(), [new Gate(SBOM, "LINE", 0.0)])
        double ratio = ratioFromReport(baseline.report, SBOM, "LINE")

        when:
        int code = CoverageGate.exitCode((["--exec", EXEC_FILE.toString(),
                                          "--classes", CLASSES_DIR.toString(),
                                          "--gate", "$SBOM:LINE:1.0"]) as String[])

        then: "a 100% gate fails exactly when the package is not fully covered"
        code == ((ratio < 1.0) ? 1 : 0)
    }

    def "given a non existent exec file when run through the exit codes then 2"() {
        when:
        int code = CoverageGate.exitCode((["--exec", "build/tmp/no-such-exec.exec",
                                          "--classes", CLASSES_DIR.toString(),
                                          "--gate", "$SBOM:LINE:0.5"]) as String[])

        then:
        code == 2
    }

    def "given no arguments when run through the exit codes then 2"() {
        when:
        int code = CoverageGate.exitCode([] as String[])

        then:
        code == 2
    }

    def "given a malformed gate through the exit codes then 2"() {
        when:
        int code = CoverageGate.exitCode((["--exec", EXEC_FILE.toString(),
                                          "--classes", CLASSES_DIR.toString(),
                                          "--gate", "org.pkg:INSTR:0.5"]) as String[])

        then:
        code == 2
    }

    def "given all options when parsed then the parsed structure is complete"() {
        when:
        Parsed parsed = CoverageGate.parse((["--exec", EXEC_FILE.toString(),
                                            "--classes", CLASSES_DIR.toString(),
                                            "--gate", "$SBOM:LINE:0.5",
                                            "--gate", "$SBOM:BRANCH:0.4"]) as String[])

        then:
        parsed.exec == EXEC_FILE
        parsed.classDirs == [CLASSES_DIR]
        parsed.gates.size() == 2
    }
}
