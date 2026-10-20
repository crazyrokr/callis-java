package org.crazyrock.callis

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import spock.lang.Specification

/**
 * M7d (A2): the native-image reflect config travels in the main resources
 * under META-INF/native-image/ (native-image's auto-discovery location), and
 * keeps the CLI's picocli metadata reflectable — without it the binary only
 * sees the built-in -h/-V options (empirically verified before the fix).
 */
class NativeImageConfigSpec extends Specification {

    private static final ObjectMapper MAPPER = new ObjectMapper()
    private static final String RESOURCE = "/META-INF/native-image/reachability-analyzer/reflect-config.json"

    def "given the reflect-config resource when resolved from the main classpath then it is at the native-image auto-discovery location"() {
        expect:
        ReachabilityAnalyzerCli.class.getResource(RESOURCE) != null
    }

    def "given the reflect-config resource when parsed then the CLI class entry registers its fields and picocli annotations"() {
        given:
        def stream = ReachabilityAnalyzerCli.class.getResourceAsStream(RESOURCE)

        when:
        JsonNode array = MAPPER.readTree(stream)
        JsonNode entry = array.get(0)
        def annotations = new ArrayList<String>()
        entry.get("annotationTypes").each { annotations << it.asText() }

        then: "one class entry for the CLI, reflectable fields and the picocli annotation types"
        array.isArray()
        array.size() == 1
        entry.get("name").asText() == "org.crazyrock.callis.ReachabilityAnalyzerCli"
        entry.get("allDeclaredFields").asBoolean()
        annotations.containsAll(["picocli.CommandLine", "picocli.CommandLine\$Option"])
    }
}
