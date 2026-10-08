package org.reachability.analyzer.analysis

import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation
import sootup.java.core.JavaSootClass
import sootup.java.core.views.JavaView
import spock.lang.Specification

/**
 * A12/R8 regression: pins SootUp 3.0.1's supported bytecode ceiling.
 * A non-empty directory whose classes SootUp cannot handle parses to zero classes
 * SILENTLY - the M3 startup guard must turn that into exit code 3.
 */
class BytecodeCeilingSpec extends Specification {

    private static final File FIXTURES = new File("src/test/resources/fixtures/bytecode")

    private static List<JavaSootClass> parse(String subDir) {
        def location = new JavaClassPathAnalysisInputLocation(new File(FIXTURES, subDir).absolutePath)
        try {
            def view = new JavaView(location)
            return view.classes.collect()
        } finally {
            location.close()
        }
    }

    def "given release 25 bytecode when parsed by SootUp then classes are found"() {
        given: "a probe compiled with --release 25 (class file major version 69)"
        String fixtureDir = "v69"

        when:
        List<JavaSootClass> classes = parse(fixtureDir)

        then: "Java 25 is the supported ceiling under SootUp 3.0.1"
        classes.any { it.name.endsWith("Release25Probe") }
    }

    def "given class file v70 when parsed then SootUp silently returns zero classes"() {
        given: "a hand-crafted class file with major version 70"
        String fixtureDir = "v70"

        when:
        List<JavaSootClass> classes = parse(fixtureDir)

        then: "no exception is thrown - the empty result is what the guard must detect"
        classes.isEmpty()
    }
}
