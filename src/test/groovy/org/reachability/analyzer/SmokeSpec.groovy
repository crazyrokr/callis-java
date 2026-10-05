package org.reachability.analyzer

import picocli.CommandLine
import spock.lang.Specification

/**
 * Proves the Spock + Groovy 4 test setup works under the Java 25 toolchain (M0 T02).
 */
class SmokeSpec extends Specification {

    def "given no arguments when cli executes then exit zero"() {
        given:
        def cli = new ReachabilityAnalyzerCli()
        def commandLine = new CommandLine(cli)

        when:
        int exitCode = commandLine.execute()

        then:
        exitCode == 0
    }

    def "given help flag when cli executes then usage is printed"() {
        given:
        def cli = new ReachabilityAnalyzerCli()
        def commandLine = new CommandLine(cli)
        def out = new ByteArrayOutputStream()
        commandLine.out = new PrintWriter(out)

        when:
        int exitCode = commandLine.execute("--help")

        then:
        exitCode == 0
        out.toString().contains("Usage:")
    }
}
