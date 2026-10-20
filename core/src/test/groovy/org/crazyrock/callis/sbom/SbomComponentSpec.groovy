package org.crazyrock.callis.sbom

import spock.lang.Specification

/** Unit tests for the SbomComponent value object. */
class SbomComponentSpec extends Specification {

    static final Purl PURL = Purl.parse("pkg:maven/g/n@1.0")

    def "given a component with version when toString then name version and purl"() {
        expect:
        new SbomComponent("n", "1.0", PURL, null).toString() == "n:1.0 (pkg:maven/g/n@1.0)"
    }

    def "given a component without version when toString then name and purl only"() {
        given:
        def noVersion = new SbomComponent("n", null, Purl.parse("pkg:maven/g/n"), null)

        expect:
        noVersion.toString() == "n (pkg:maven/g/n)"
    }

    def "given a component when bomRef is present or absent then getter returns it"() {
        expect:
        new SbomComponent("n", "1.0", PURL, "bom-1").getBomRef() == "bom-1"
        new SbomComponent("n", "1.0", PURL, null).getBomRef() == null
    }

    def "given the getters when read then constructor values are returned"() {
        given:
        def c = new SbomComponent("n", "1.0", PURL, "bom-1")

        expect:
        c.name == "n"
        c.version == "1.0"
        c.purl == PURL
        c.bomRef == "bom-1"
    }

    def "given a null name or purl when constructed then NullPointerException"() {
        when:
        new SbomComponent(args[0] as String, "1.0", args[1] as Purl, null)

        then:
        thrown(NullPointerException)

        where:
        args << [["", null], [null, PURL]]
    }
}
