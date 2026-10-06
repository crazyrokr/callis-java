package org.reachability.analyzer

import picocli.CommandLine
import spock.lang.Specification

/**
 * CLI contract (M1 T11): help/version, exit-code contract A8, and the
 * --dry-run-sbom debug mode. Replaces the M0 SmokeSpec.
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

    def "given no arguments when executed then skeleton notice and exit usage error"() {
        when:
        int exitCode = runCli()

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedOut.toString().contains("not wired yet")
    }

    def "given dry-run-sbom with fixture when executed then component table and exit zero"() {
        when:
        int exitCode = runCli("--dry-run-sbom", "--sbom", "src/test/resources/fixtures/bom.json")

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

    def "given dry-run-sbom with spdx file when executed then exit usage error and explicit message"() {
        given:
        File spdx = File.createTempFile("spdx", ".json", new File("build"))
        spdx.text = '{"spdxVersion": "SPDX-2.3"}'
        spdx.deleteOnExit()

        when:
        int exitCode = runCli("--dry-run-sbom", "--sbom", spdx.absolutePath)

        then:
        exitCode == CliResult.USAGE_ERROR.exitCode
        capturedErr.toString().contains("SPDX")
    }
}
