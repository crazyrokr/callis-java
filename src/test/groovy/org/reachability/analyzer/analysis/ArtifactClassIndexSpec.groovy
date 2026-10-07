package org.reachability.analyzer.analysis

import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path

/**
 * T41 artifact index tests (M4): jar file name to binary class names —
 * plain and versioned stems, version-preferred lookup with fallback,
 * group-prefixed component names, corrupt jars warned and skipped,
 * and no-match returning the empty set.
 */
class ArtifactClassIndexSpec extends Specification {

    private static final File STUB_JAR = new File("src/test/resources/fixtures/mini-app/stublib.jar")

    @TempDir
    Path workDir

    /** Copies the entries of sourceJar under the given prefix into a new zip. */
    private void extractEntries(Path sourceJar, Path targetJar, String prefix) {
        new java.util.zip.ZipFile(sourceJar.toFile()).withCloseable { zsrc ->
            new java.util.zip.ZipOutputStream(java.nio.file.Files.newOutputStream(targetJar)).withCloseable { zout ->
                zsrc.entries().each { e ->
                    if (!e.isDirectory() && e.name.startsWith(prefix)) {
                        zout.putNextEntry(new java.util.zip.ZipEntry(e.name))
                        zsrc.getInputStream(e).withCloseable { in -> in.transferTo(zout) }
                        zout.closeEntry()
                    }
                }
            }
        }
    }

    def "given the fixture jar when queried by group-prefixed name and version then its binary classes are returned"() {
        when:
        Set<String> classes = new ArtifactClassIndex([STUB_JAR.toPath()]).classesFor("stublib:stublib", "1.0")

        then:
        classes.containsAll(["stublib.Stub", "stublib.Marked", "libpkg.Tool",
                             "jakarta.servlet.http.HttpServlet"])
    }

    def "given a plain component name when queried then the group prefix is not required"() {
        when:
        Set<String> classes = new ArtifactClassIndex([STUB_JAR.toPath()]).classesFor("stublib", null)

        then:
        classes.contains("stublib.Stub")
    }

    def "given versioned and plain jars of one artifact when queried by version then the versioned jar wins"() {
        given: "stublib-1.0.jar holds the full fixture; stublib-2.0.jar holds only the libpkg package"
        def v1 = workDir.resolve("stublib-1.0.jar")
        Files.copy(STUB_JAR.toPath(), v1)
        def v2 = workDir.resolve("stublib-2.0.jar")
        extractEntries(STUB_JAR.toPath(), v2, "libpkg/")
        def index = new ArtifactClassIndex([v1, v2])

        expect: "the 1.0 jar carries the full fixture set; the 2.0 jar only the tool"
        index.classesFor("stublib:stublib", "1.0").containsAll(
                ["stublib.Stub", "stublib.Marked", "libpkg.Tool", "jakarta.servlet.http.HttpServlet"])
        index.classesFor("stublib:stublib", "2.0") == ["libpkg.Tool"] as Set
        !index.classesFor("stublib:stublib", "2.0").contains("stublib.Stub")

        and: "without a version the union of both jars is returned"
        index.classesFor("stublib:stublib", null).containsAll(["stublib.Stub", "libpkg.Tool"])

        and: "an unknown version falls back to the union (never to nothing)"
        index.classesFor("stublib:stublib", "9.9").containsAll(["stublib.Stub", "libpkg.Tool"])
    }

    def "given a jar whose stem is not version-like when indexed then the whole stem is the artifact name"() {
        given: "jakarta-servlet.jar: the part after the last dash is a word, not a version"
        def jar = workDir.resolve("jakarta-servlet.jar")
        extractEntries(STUB_JAR.toPath(), jar, "jakarta/")
        def index = new ArtifactClassIndex([jar])

        expect:
        index.classesFor("jakarta:jakarta-servlet", "5.0").contains("jakarta.servlet.http.HttpServlet")
        index.classesFor("jakarta:jakarta-servlet", null).contains("jakarta.servlet.annotation.WebServlet")
    }

    def "given a component name matching no jar when queried then the empty set is returned"() {
        when:
        Set<String> classes = new ArtifactClassIndex([STUB_JAR.toPath()]).classesFor("log4j:log4j-core", "2.14.1")

        then:
        classes.isEmpty()
    }

    def "given a corrupt jar when indexed then a warning is collected and the other jars stay usable"() {
        given:
        def broken = workDir.resolve("broken.jar")
        Files.write(broken, "not a zip".bytes)

        when:
        def index = new ArtifactClassIndex([broken, STUB_JAR.toPath()])

        then:
        index.warnings().size() == 1
        index.warnings()[0].contains("broken.jar")
        index.classesFor("stublib:stublib", "1.0").contains("stublib.Stub")
    }

    def "given a jar without the jar extension when indexed then the file name is the artifact name"() {
        given:
        def plain = workDir.resolve("stublib")
        Files.copy(STUB_JAR.toPath(), plain)

        when:
        Set<String> classes = new ArtifactClassIndex([plain]).classesFor("stublib:stublib", null)

        then:
        classes.contains("stublib.Stub")
    }

    def "given an empty version when queried then all same-named jars are used"() {
        given:
        def v1 = workDir.resolve("stublib-1.0.jar")
        Files.copy(STUB_JAR.toPath(), v1)
        def v2 = workDir.resolve("stublib-2.0.jar")
        extractEntries(STUB_JAR.toPath(), v2, "libpkg/")
        def index = new ArtifactClassIndex([v1, v2])

        expect:
        index.classesFor("stublib:stublib", "").containsAll(["stublib.Stub", "libpkg.Tool"])
    }

    def "given a null component name when queried then the empty set is returned"() {
        expect:
        new ArtifactClassIndex([STUB_JAR.toPath()]).classesFor(null, null).isEmpty()
    }

    def "given a jar whose version part carries an underscore when indexed then it is version-like"() {
        given:
        def jar = workDir.resolve("stublib-1_0.jar")
        Files.copy(STUB_JAR.toPath(), jar)
        def index = new ArtifactClassIndex([jar])

        expect: "1_0 parses as a version; an unknown version falls back to the union"
        index.classesFor("stublib:stublib", "1_0").contains("stublib.Stub")
        index.classesFor("stublib:stublib", "1.0").contains("stublib.Stub")
    }

    def "given a jar that also carries a text file and a directory when indexed then non-class entries are skipped"() {
        given: "a zip with one class, a README.txt, and a directory entry"
        def jar = workDir.resolve("mixed.jar")
        new java.util.zip.ZipFile(STUB_JAR).withCloseable { zsrc ->
            new java.util.zip.ZipOutputStream(java.nio.file.Files.newOutputStream(jar)).withCloseable { zout ->
                zsrc.entries().each { e ->
                    if (e.name.startsWith("libpkg/") && e.name.endsWith(".class")) {
                        zout.putNextEntry(new java.util.zip.ZipEntry(e.name))
                        zsrc.getInputStream(e).withCloseable { in -> in.transferTo(zout) }
                        zout.closeEntry()
                    }
                }
                zout.putNextEntry(new java.util.zip.ZipEntry("README.txt"))
                zout.write("not a class".bytes)
                zout.closeEntry()
                zout.putNextEntry(new java.util.zip.ZipEntry("docs/"))
                zout.closeEntry()
            }
        }

        when:
        def index = new ArtifactClassIndex([jar])

        then:
        index.warnings().isEmpty()
        index.classesFor("mixed:mixed", null) == ["libpkg.Tool"] as Set
    }

    def "given a directory path when indexed then a warning is collected and no crash"() {
        when: "the path has no file name, so the index falls back to the path string"
        def index = new ArtifactClassIndex([Path.of("/")])

        then:
        index.warnings().size() == 1
        index.classesFor("stublib:stublib", null).isEmpty()
    }
}
