package org.crazyrock.callis

import org.crazyrock.callis.analysis.TestPermissions
import org.crazyrock.callis.osv.SnapshotChecksum
import picocli.CommandLine
import spock.lang.Specification

import java.nio.file.Path

/**
 * CLI contract (M1 T11, M2 T24): help/version, exit-code contract A8,
 * the --dry-run-sbom debug mode, and the --dry-run-match candidate mode.
 * Replaces the M0 SmokeSpec.
 */
class CliSpec extends Specification {

    private PrintStream originalOut
    private PrintStream originalErr
    private ByteArrayOutputStream capturedOut
    private ByteArrayOutputStream capturedErr

    private int runCli(String... args) {
        def cli = new ReachabilityAnalyzerCli()
        return new CommandLine(cli).execute(*args)
    }

    def setup() {
        originalOut = System.out
        originalErr = System.err
        capturedOut = new ByteArrayOutputStream()
        capturedErr = new ByteArrayOutputStream()
        System.setOut(new PrintStream(capturedOut))
        System.setErr(new PrintStream(capturedErr))
    }

    def cleanup() {
        System.setOut(originalOut)
        System.setErr(originalErr)
        // The default --output writes reports next to the working directory
        new File("reachability-report.json").delete()
        new File("reachability-report.junit.xml").delete()
    }

    def "given help flag when executed then usage printed and exit zero"() {
        when:
        int exitCode = runCli("--help")

        then:
        exitCode == 0
        capturedOut.toString().contains("Usage:")
        capturedOut.toString().contains("--sbom")
    }

    def "given version flag when executed then version printed and exit zero"() {
        when:
        int exitCode = runCli("--version")

        then:
        exitCode == 0
        capturedOut.toString().contains("0.1.0-SNAPSHOT")
    }

    def "given no arguments when executed then missing-option error and exit usage error"() {
        when: "the pipeline is wired (M4): running it without the required options is a usage error"
        int exitCode = runCli()

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("analysis requires --sbom, --osv-dir and --app-classes")
    }

    def "given dry-run-sbom with fixture when executed then component table and exit zero"() {
        when:
        int exitCode = runCli("--dry-run-sbom", "--sbom", "../core/src/test/resources/fixtures/bom.json")

        then:
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("log4j-core")
        capturedOut.toString().contains("2.14.1")
        capturedOut.toString().contains("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        capturedOut.toString().contains("commons-lang3")
    }

    def "given dry-run-sbom without sbom option when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-sbom")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("--sbom")
    }

    def "given dry-run-sbom with missing file when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-sbom", "--sbom", "build/no-such-bom.json")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("cannot read SBOM")
    }

    def "given dry-run-sbom with the spdx-mini fixture when executed then the maven package is printed and exit zero"() {
        given: "SPDX 2.x is a supported input since M7c"
        File spdx = new File("../core/src/test/resources/fixtures/spdx-mini.json")

        when:
        int exitCode = runCli("--dry-run-sbom", "--sbom", spdx.absolutePath)

        then:
        exitCode == CliResult.OK.exitCode
        def out = capturedOut.toString()
        out.contains("stublib")
        out.contains("pkg:maven/stublib/stublib@1.0")

        and: "the package without a purl is a warning, same contract as CycloneDX"
        capturedErr.toString().contains("WARNING: package no-purl-lib has no purl; skipped")
    }

    def "given dry-run-sbom with an spdx 3.x file when executed then exit usage error and the not-supported message"() {
        given:
        File spdx = File.createTempFile("spdx3", ".json", new File("build"))
        spdx.text = '{"spdxVersion": "SPDX-3.0.1", "name": "x"}'
        spdx.deleteOnExit()

        when:
        int exitCode = runCli("--dry-run-sbom", "--sbom", spdx.absolutePath)

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("SPDX-3.0.1")
        capturedErr.toString().contains("2.x")
    }

    def "given dry-run-match with the fixture sbom and osv records when executed then the log4shell candidate is printed and exit zero"() {
        when:
        int exitCode = runCli("--dry-run-match",
                "--sbom", "../core/src/test/resources/fixtures/bom.json",
                "--osv-dir", "../core/src/test/resources/fixtures/osv")

        then:
        exitCode == CliResult.OK.exitCode
        def out = capturedOut.toString()
        out.contains("GHSA-jfh8-c2jp-5v3q")
        out.contains("CVE-2021-44228")
        out.contains("log4j-core")
        out.contains("2.14.1")
        out.contains("org.apache.logging.log4j:log4j-core")
    }

    def "given dry-run-match without the osv-dir option when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-match", "--sbom", "../core/src/test/resources/fixtures/bom.json")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("--osv-dir")
    }

    def "given dry-run-match without the sbom option when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-match", "--osv-dir", "../core/src/test/resources/fixtures/osv")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("--sbom")
    }

    def "given dry-run-match with a non-existent osv directory when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-match",
                "--sbom", "../core/src/test/resources/fixtures/bom.json",
                "--osv-dir", "build/no-such-osv-dir")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("cannot read OSV directory")
    }

    def "given dry-run-match with an empty osv directory when executed then no candidates and exit zero"() {
        given:
        File emptyDir = new File("build/tmp/osv-empty").toPath().toFile()
        emptyDir.mkdirs()

        when:
        int exitCode = runCli("--dry-run-match",
                "--sbom", "../core/src/test/resources/fixtures/bom.json",
                "--osv-dir", emptyDir.absolutePath)

        then:
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("No vulnerability candidates")
    }

    def "given dry-run-match with a non-empty directory of malformed records when executed then exit analysis failure (fail-safe)"() {
        given:
        File corruptDir = new File("build/tmp/osv-corrupt").toPath().toFile()
        corruptDir.mkdirs()
        new File(corruptDir, "corrupt.json").text = "not a json record"

        when:
        int exitCode = runCli("--dry-run-match",
                "--sbom", "../core/src/test/resources/fixtures/bom.json",
                "--osv-dir", corruptDir.absolutePath)

        then:
        exitCode == CliResult.ANALYSIS_FAILURE.exitCode
        capturedErr.toString().contains("zero valid records")
    }

    def "given dry-run-match with a wrong osv-checksum when executed then exit usage error naming both values"() {
        when:
        int exitCode = runCli("--dry-run-match",
                "--sbom", "../core/src/test/resources/fixtures/bom.json",
                "--osv-dir", "../core/src/test/resources/fixtures/osv",
                "--osv-checksum", "0000000000000000000000000000000000000000000000000000000000000000")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        def err = capturedErr.toString()
        err.contains("checksum mismatch")
        err.contains("0000000000000000000000000000000000000000000000000000000000000000")
    }

    def "given dry-run-match with the matching osv-checksum when executed then exit zero"() {
        when:
        int exitCode = runCli("--dry-run-match",
                "--sbom", "../core/src/test/resources/fixtures/bom.json",
                "--osv-dir", "../core/src/test/resources/fixtures/osv",
                "--osv-checksum", SnapshotChecksum.sha256OfDirectory(Path.of("../core/src/test/resources/fixtures/osv")))

        then:
        exitCode == CliResult.OK.exitCode
    }

    private File miniAppCpFile() {
        File cp = new File("build/tmp/mini-app-cp.txt")
        cp.parentFile.mkdirs()
        cp.text = new File("../core/src/test/resources/fixtures/mini-app/stublib.jar").absolutePath
        return cp
    }

    private static final String MINI_APP_CLASSES = "../core/src/test/resources/fixtures/mini-app/classes"

    def "given dry-run-graph on the mini-app when executed then the graph is built and the size is printed"() {
        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath)

        then:
        exitCode == CliResult.OK.exitCode
        def out = capturedOut.toString()
        out.contains("call graph (RTA): ")
        out.contains(" nodes, ")
    }

    def "given dry-run-graph with the cha flag when executed then the CHA graph is built"() {
        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--cha")

        then:
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("call graph (CHA): ")
    }

    def "given dry-run-graph with the pointer-analysis flag when executed then the SPARK graph is built"() {
        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--pointer-analysis")

        then:
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("call graph (SPARK): ")
    }

    def "given dry-run-graph without the classpath file when executed then the app classes alone are analyzed"() {
        when:
        int exitCode = runCli("--dry-run-graph", "--app-classes", MINI_APP_CLASSES)

        then:
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("call graph (RTA): ")
    }

    def "given dry-run-graph with verbose when executed then the detected entry points are printed"() {
        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "-v")

        then:
        exitCode == CliResult.OK.exitCode
        def out = capturedOut.toString()
        out.contains("Detected entry points:")
        out.contains("demo.Main: void main")
    }

    def "given dry-run-graph with an entry point override when executed then the override is used"() {
        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", MINI_APP_CLASSES,
                "--entry-points", "demo.Main#main")

        then:
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("call graph (RTA): ")
    }

    def "given dry-run-graph on classes above the bytecode ceiling when executed then exit analysis failure with the guard message"() {
        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", "../core/src/test/resources/fixtures/bytecode/v70")

        then:
        exitCode == CliResult.ANALYSIS_FAILURE.exitCode
        def err = capturedErr.toString()
        err.contains("ceiling")
        err.contains("69")
    }

    def "given dry-run-graph on a directory of only corrupt class files when executed then exit analysis failure"() {
        given:
        File corruptDir = new File("build/tmp/corrupt-classes")
        corruptDir.mkdirs()
        new File(corruptDir, "Corrupt.class").bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08] as byte[]

        when:
        int exitCode = runCli("--dry-run-graph", "--app-classes", corruptDir.absolutePath)

        then:
        exitCode == CliResult.ANALYSIS_FAILURE.exitCode
        capturedErr.toString().contains("zero classes")
    }

    def "given dry-run-graph on a class directory without entry points when executed then exit analysis failure"() {
        given: "Business is a plain interface: no main, no annotations, no callback. " +
                "Package-consistent layout: SootUp silently drops .class files whose declared " +
                "package does not match their path under the classpath entry (verified 2026-10-06)."
        File noEntryBase = new File("build/tmp/no-entry-classes")
        if (noEntryBase.exists()) {
            java.nio.file.Files.walk(noEntryBase.toPath())
                    .sorted(java.util.Comparator.reverseOrder())
                    .forEach { p -> p.toFile().delete() }
        }
        java.nio.file.Files.createDirectories(noEntryBase.toPath().resolve("demo"))
        java.nio.file.Files.copy(new File("../core/src/test/resources/fixtures/mini-app/classes/demo/Business.class").toPath(),
                noEntryBase.toPath().resolve("demo").resolve("Business.class"))

        when:
        int exitCode = runCli("--dry-run-graph", "--app-classes", noEntryBase.absolutePath)

        then:
        exitCode == CliResult.ANALYSIS_FAILURE.exitCode
        capturedErr.toString().contains("no entry points detected")
    }

    def "given dry-run-graph on an empty class directory when executed then exit analysis failure"() {
        given: "no class files: nothing to detect, so no entry points"
        File emptyDir = new File("build/tmp/empty-classes")
        emptyDir.mkdirs()

        when:
        int exitCode = runCli("--dry-run-graph", "--app-classes", emptyDir.absolutePath)

        then:
        exitCode == CliResult.ANALYSIS_FAILURE.exitCode
        capturedErr.toString().contains("no entry points detected")
    }

    def "given dry-run-graph with a missing app class directory when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-graph", "--app-classes", "build/tmp/no-such-classes")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("does not exist")
    }

    def "given dry-run-graph without the app classes option when executed then exit usage error"() {
        when:
        int exitCode = runCli("--dry-run-graph")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("--app-classes")
    }

    def "given dry-run-graph with a classpath file listing a missing jar when executed then a warning is printed and the run succeeds"() {
        given:
        File cp = new File("build/tmp/mini-app-cp-missing.txt")
        cp.parentFile.mkdirs()
        cp.text = "${cp.parentFile}/missing.jar"

        when:
        int exitCode = runCli("--dry-run-graph",
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", cp.absolutePath)

        then:
        exitCode == CliResult.OK.exitCode
        capturedErr.toString().contains("missing.jar")
        capturedOut.toString().contains("call graph (RTA): ")
    }

    // ------------------------------------------------------------------
    // M4 T44: the full pipeline (SBOM + OSV + call graph + verdicts).
    // ------------------------------------------------------------------

    private static final String BOM_MINI = "../core/src/test/resources/fixtures/bom-mini.json"
    private static final String OSV_MINI = "../core/src/test/resources/fixtures/osv-mini"
    private static final String MAPPINGS = "../core/src/test/resources/fixtures/mappings/valid.json"

    def "given a reachable vulnerability in the pipeline when executed then exit one with a CRITICAL line and the call path"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS)

        then: "the mapped method is called from the app: REACHABLE, exit 1, path printed hop by hop"
        exitCode == CliResult.REACHABLE_VULNERABILITIES.exitCode
        def out = capturedOut.toString()
        out.contains("CRITICAL: VULN-POS")
        out.contains("REACHABLE")
        out.contains("demo.MainDanger#main -> stublib.Stub#danger")
        out.contains("1 candidate(s): 1 reachable")
    }

    def "given the same pipeline with the vulnerable call excluded from the entry points when executed then exit zero with a NOTICE"() {
        when: "--entry-points demo.Main#main: Main calls only safe(); the artifact is still on the classpath"
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--entry-points", "demo.Main#main")

        then: "UNREACHABLE with the A14 onClasspath notice, exit 0"
        exitCode == CliResult.OK.exitCode
        def out = capturedOut.toString()
        out.contains("NOTICE: VULN-POS")
        out.contains("UNREACHABLE")
        out.contains("artifact present in classpath")
        out.contains("1 candidate(s): 0 reachable")
    }

    def "given the pipeline with an osv directory without matching records when executed then exit zero with the zero-candidate summary"() {
        given:
        File emptyDir = new File("build/tmp/osv-pipeline-empty")
        emptyDir.mkdirs()

        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", emptyDir.absolutePath,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath)

        then: "no candidates: the analysis is skipped entirely"
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("No vulnerability candidates")
        !capturedOut.toString().contains("call graph")
    }

    def "given a previous run's reports and a zero-candidate run when executed then the stale reports are removed"() {
        given: "a report left behind by an earlier, vulnerable run"
        File emptyDir = new File("build/tmp/osv-pipeline-empty")
        emptyDir.mkdirs()
        def staleJson = new File("build/tmp/m5-stale.json")
        def staleXml = new File("build/tmp/m5-stale.junit.xml")
        staleJson.text = '{"stale": true}'
        staleXml.text = "<testsuite/>"

        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", emptyDir.absolutePath,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--output", "build/tmp/m5-stale")

        then: "the early exit must not leave a previous run's report behind"
        exitCode == CliResult.OK.exitCode
        capturedOut.toString().contains("No vulnerability candidates")
        !staleJson.exists()
        !staleXml.exists()
    }

    def "given the pipeline without the required options when executed then exit usage error"() {
        when:
        int exitCode = runCli("--sbom", BOM_MINI, "--osv-dir", OSV_MINI)

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("analysis requires --sbom, --osv-dir and --app-classes")
    }

    def "given the pipeline with a malformed mappings file when executed then exit usage error"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", "../core/src/test/resources/fixtures/mappings/malformed.json")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("malformed.json")
        capturedErr.toString().contains("object")
    }

    def "given the pipeline with a missing mappings file when executed then exit usage error"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", "build/tmp/no-such-mappings.json")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("cannot read mappings")
    }

    def "given the pipeline with the cha flag when executed then the verdicts hold on the CHA graph"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--cha")

        then: "CHA is less precise but the same mapped call is still reachable"
        exitCode == CliResult.REACHABLE_VULNERABILITIES.exitCode
        capturedOut.toString().contains("CRITICAL: VULN-POS")
    }

    def "given the pipeline with the pointer-analysis flag when executed then the verdicts hold on the SPARK graph"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--pointer-analysis")

        then: "SPARK prunes the instantiated-but-undispatched call, yet the mapped call is still reachable"
        exitCode == CliResult.REACHABLE_VULNERABILITIES.exitCode
        def out = capturedOut.toString()
        out.contains("CRITICAL: VULN-POS")
        out.contains("REACHABLE")
        out.contains("demo.MainDanger#main -> stublib.Stub#danger")
    }

    def "given both the cha and the pointer-analysis flags when executed then exit usage error"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--pointer-analysis",
                "--cha")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("mutually exclusive")
    }

    // ------------------------------------------------------------------
    // M5 T51-T54: the reporting engine (JSON + JUnit XML + console table).
    // ------------------------------------------------------------------

    private static final String M5_REPORT = "build/tmp/m5-report"

    def "given a reachable vulnerability in the pipeline when executed then both reports are written next to the output base name"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--format", "json,junitxml,sarif",
                "--output", M5_REPORT)

        then: "the JSON report carries the verdict, the purl, the OSV severity and the range evidence"
        exitCode == CliResult.REACHABLE_VULNERABILITIES.exitCode
        def json = new File(M5_REPORT + ".json").text
        json.contains('"verdict" : "REACHABLE"')
        json.contains("pkg:maven/stublib/stublib@1.0")
        json.contains("CVSS_V3")
        json.contains("range#0 (introduced=0, fixed=2.0)")
        json.contains("demo.MainDanger#main")

        and: "the JUnit XML suite fails exactly because the pipeline must fail"
        def xml = new File(M5_REPORT + ".junit.xml").text
        xml.contains("<testsuite name=\"reachability\" tests=\"1\" failures=\"1\"")
        xml.contains("<failure message=\"reachable\">")
        xml.contains("demo.MainDanger#main -&gt; stublib.Stub#danger")

        and: "the SARIF document (M7c) carries the finding as an error result"
        def sarif = new File(M5_REPORT + ".sarif").text
        sarif.contains('"version" : "2.1.0"')
        sarif.contains('"ruleId" : "VULN-POS"')
        sarif.contains('"level" : "error"')
        sarif.contains("demo.MainDanger#main -> stublib.Stub#danger")
    }

    def "given the pipeline with only the json format when executed then only the json report is written"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--entry-points", "demo.Main#main",
                "--format", "json",
                "--output", "build/tmp/m5-json-only")

        then:
        exitCode == CliResult.OK.exitCode
        new File("build/tmp/m5-json-only.json").exists()
        !new File("build/tmp/m5-json-only.junit.xml").exists()
    }

    def "given the pipeline with only the sarif format when executed then only the sarif report is written"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--format", "sarif",
                "--output", "build/tmp/m7c-sarif-only")

        then:
        exitCode == CliResult.REACHABLE_VULNERABILITIES.exitCode
        new File("build/tmp/m7c-sarif-only.sarif").exists()
        !new File("build/tmp/m7c-sarif-only.json").exists()
        !new File("build/tmp/m7c-sarif-only.junit.xml").exists()
    }

    def "given an unknown report format when executed then exit usage error"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--format", "html")

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("unknown report format")
        capturedErr.toString().contains("html")
    }

    def "given a non-writable report destination when executed then exit analysis failure"() {
        given:
        File dir = new File("build/tmp/m5-readonly")
        dir.mkdirs()
        TestPermissions.withoutOwnerWrite(dir.toPath())

        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--entry-points", "demo.Main#main",
                "--output", dir.absolutePath + "/report")

        then:
        exitCode == CliResult.ANALYSIS_FAILURE.exitCode
        capturedErr.toString().contains("cannot write report")

        cleanup:
        TestPermissions.ownerReadWriteExecute(dir.toPath())
    }

    def "given a reachable vulnerability in the pipeline with verbose when executed then the summary table and the written reports are printed"() {
        when:
        int exitCode = runCli(
                "--sbom", BOM_MINI,
                "--osv-dir", OSV_MINI,
                "--app-classes", MINI_APP_CLASSES,
                "--classpath-file", miniAppCpFile().absolutePath,
                "--mappings", MAPPINGS,
                "--output", "build/tmp/m5-verbose",
                "-v")

        then: "the T54 table shows id, component, verdict and the path head; verbose names the written files"
        exitCode == CliResult.REACHABLE_VULNERABILITIES.exitCode
        def out = capturedOut.toString()
        out.contains("VULN ID")
        out.contains("PATH")
        out.contains("REACHABLE")
        out.contains("demo.MainDanger#main")
        out.contains("reports written")
        out.contains("build/tmp/m5-verbose.json")
    }
}
