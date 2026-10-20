package org.crazyrock.callis.sbom

import spock.lang.Specification
import spock.lang.Unroll

/** Purl parsing/normalization (M1 T12). */
@Unroll
class PurlSpec extends Specification {

    def "given purl '#purl' when parsed then type=#type namespace=#namespace name=#name version=#version"() {
        when:
        Purl parsed = Purl.parse(purl)

        then:
        parsed.type == type
        parsed.namespace == namespace
        parsed.name == name
        parsed.version == version

        where:
        purl                                  | type  || namespace            || name       || version
        "pkg:maven/org.apache.logging/log4j-core@2.14.1" | "maven" || "org.apache.logging" || "log4j-core" || "2.14.1"
        "pkg:maven/org.apache.logging/log4j-core"       | "maven" || "org.apache.logging" || "log4j-core" || null
        "pkg:maven/log4j-core"                                | "maven" || ""                 || "log4j-core" || null
        "pkg:maven/org.apache.commons/commons-lang3@3.14.0?type=jar" | "maven" || "org.apache.commons" || "commons-lang3" || "3.14.0"
        "pkg:maven/g/n@"                                   | "maven" || "g"                || "n"          || null
        "pkg:maven/g/n@1.0#path/inside"                     | "maven" || "g"                || "n"          || "1.0"
        "pkg:pypi/django@1.0"                               | "pypi"  || ""                 || "django"     || "1.0"
        "pkg:MAVEN/org.apache.logging/log4j-core@2.14.1"    | "maven" || "org.apache.logging" || "log4j-core" || "2.14.1"
    }

    def "given maven purl with group when qualifiedName then group:name"() {
        expect:
        Purl.parse(purl).qualifiedName == expected

        where:
        purl                                        | expected
        "pkg:maven/org.apache.logging/log4j-core@2.14.1" | "org.apache.logging:log4j-core"
        "pkg:maven/log4j-core"                          | "log4j-core"
    }

    def "given qualifiers and subpath when parsed then kept raw"() {
        when:
        Purl parsed = Purl.parse("pkg:maven/g/n@1.0?os.classifier=linux#x/y")

        then:
        parsed.qualifiers == "os.classifier=linux"
        parsed.subpath == "x/y"
    }

    def "given malformed purl '#purl' when parsed then IllegalArgumentException"() {
        when:
        Purl.parse(purl)

        then:
        thrown(IllegalArgumentException)

        where:
        purl << ["", "not-a-purl", "pkg:", "pkg:maven", "pkg:maven/", "pkg:maven/g/", "pkg://n@1"]
    }

    def "given round-trip when toString reparsed then same purl"() {
        given:
        Purl original = Purl.parse(purl)

        when:
        Purl reparsed = Purl.parse(original.toString())

        then:
        reparsed == original
        reparsed.hashCode() == original.hashCode()

        where:
        purl << [
                "pkg:maven/org.apache.logging/log4j-core@2.14.1",
                "pkg:maven/org.apache.logging/log4j-core",
                "pkg:maven/log4j-core",
                "pkg:maven/org.apache.commons/commons-lang3@3.14.0?type=jar",
                "pkg:pypi/django@1.0",
                "pkg:maven/g/n@1.0#path/inside"
        ]
    }

    def "given the same instance when equals then true"() {
        given:
        def p = Purl.parse("pkg:maven/g/n@1.0")

        expect:
        p.equals(p)
    }

    def "given a non purl object when equals then false"() {
        given:
        def p = Purl.parse("pkg:maven/g/n@1.0")

        expect:
        !p.equals("pkg:maven/g/n@1.0")
        !p.equals(null)
        !p.equals(new Object())
    }

    def "given isMaven when type maven then true, otherwise false"() {
        expect:
        Purl.parse(purl).isMaven() == expected

        where:
        purl                          | expected
        "pkg:maven/g/n@1.0"          | true
        "pkg:pypi/django@1.0"        | false
        "pkg:npm/@scope/pkg@2.0.0"   | false
    }
}
