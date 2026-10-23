package org.reachability.gradle

import org.gradle.testkit.runner.BuildResult
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Path

/**
 * M7e (A10): plugin wiring — the reachability extension and the
 * checkReachability task exist on a java project with the documented
 * defaults, the task is wired to the main source set's output and the
 * project's runtime classpath, a project without the java plugin gets an
 * explicit error, the maxHeapSize convention reaches the task, extension
 * values reach the task inputs, the task carries the cacheable
 * content-sensitive input pins, and the work action carries the 9.8 worker
 * parameter contract.
 *
 * The project-level assertions run against TestKit fixture builds (see
 * FixtureProject for why ProjectBuilder is off the table under Groovy 6);
 * each fixture dumps its live extension/task values to a file, so the
 * assertions check exactly the values the original in-project assertions
 * checked. The task and work-action pins are pure reflection and need no
 * project at all.
 */
class ReachabilityPluginSpec extends Specification {

    @TempDir
    Path projectDir

    def "given a project with the java plugin when the reachability plugin is applied then the extension and task exist with defaults"() {
        given:
        FixtureProject fixture = FixtureProject.withJavaPlugin(projectDir, "")

        when:
        Map<String, String> dump = fixture.wiringDump()

        then: "the extension and task exist with the documented defaults"
        dump.get("task.exists") == "true"
        dump.get("extension.exists") == "true"
        dump.get("extension.formats") == "json,junitxml"
        dump.get("extension.cha") == "false"
        dump.get("extension.pointerAnalysis") == "false"
        dump.get("extension.entryPoints") == "[]"
        dump.get("extension.callbackInterfaces") == "[]"

        and: "the task is wired to the main source set output and the runtime classpath"
        dump.get("task.dependsOn") == "[compileJava]"
        dump.get("task.classpathJars").split("|").toList().containsAll(dump.get("runtimeClasspath").split("|").toList())
        dump.get("task.appClasses") == dump.get("mainClasses")
        dump.get("task.group") == "verification"
    }

    def "given a project without the java plugin when the reachability plugin is applied then a clear error"() {
        given:
        FixtureProject fixture = FixtureProject.withoutJavaPlugin(projectDir)

        when:
        BuildResult result = fixture.runFailing("help", "--stacktrace")

        then: "Gradle wraps the plugin application failure; the cause carries the clear message"
        result.output.contains("java.lang.IllegalStateException")
        result.output.contains("java plugin")
    }

    def "given the task class when it is inspected then the cacheable and content-sensitive input pins hold"() {
        given:
        def taskClass = CheckReachabilityTask
        def appMethod = taskClass.getMethod("getAppClasses")
        def classpathMethod = taskClass.getMethod("getClasspathJars")
        def bomMethod = taskClass.getMethod("getBomFileContent")
        def osvMethod = taskClass.getMethod("getOsvDirContent")
        def mappingsMethod = taskClass.getMethod("getMappingsContent")

        expect: "the task is cacheable; content, not paths, drives the up-to-date check"
        taskClass.isAnnotationPresent(org.gradle.api.tasks.CacheableTask)
        classpathMethod.isAnnotationPresent(org.gradle.api.tasks.Classpath)
        appMethod.isAnnotationPresent(org.gradle.api.tasks.InputDirectory)
        appMethod.getAnnotation(org.gradle.api.tasks.PathSensitive).value() ==
                org.gradle.api.tasks.PathSensitivity.NONE
        bomMethod.isAnnotationPresent(org.gradle.api.tasks.InputFile)
        bomMethod.isAnnotationPresent(org.gradle.api.tasks.Optional)
        bomMethod.getAnnotation(org.gradle.api.tasks.PathSensitive).value() ==
                org.gradle.api.tasks.PathSensitivity.NONE
        osvMethod.isAnnotationPresent(org.gradle.api.tasks.InputDirectory)
        osvMethod.isAnnotationPresent(org.gradle.api.tasks.Optional)
        mappingsMethod.isAnnotationPresent(org.gradle.api.tasks.InputFile)
        mappingsMethod.isAnnotationPresent(org.gradle.api.tasks.Optional)
    }

    def "given the extension when the task is realized then the maxHeapSize default and values reach the task"() {
        given:
        FixtureProject defaultFixture = FixtureProject.withJavaPlugin(projectDir.resolve("default"), "")
        FixtureProject configuredFixture =
                FixtureProject.withJavaPlugin(projectDir.resolve("configured"), "reachability {\n    maxHeapSize = '2g'\n}\n")

        when: "the default is dumped"
        Map<String, String> defaultDump = defaultFixture.wiringDump()

        then: "the convention is 1g"
        defaultDump.get("task.maxHeapSize") == "1g"

        when: "the user sets a value"
        Map<String, String> configuredDump = configuredFixture.wiringDump()

        then:
        configuredDump.get("task.maxHeapSize") == "2g"
    }

    def "given the work action class when it is inspected then the 9.8 worker parameter contract holds"() {
        given:
        def actionClass = ReachabilityWorkAction

        expect: "the action carries the internal marker and the @Inject constructor the worker injects parameters through"
        org.gradle.workers.internal.ProvidesWorkResult.isAssignableFrom(actionClass)
        def ctor = actionClass.getConstructor(ReachabilityWorkAction.Params,
                org.gradle.internal.instantiation.InstanceGenerator)
        ctor.isAnnotationPresent(javax.inject.Inject)
    }

    def "given extension values when the task is realized then they reach the task inputs"() {
        given:
        FixtureProject fixture = FixtureProject.withJavaPlugin(projectDir,
                "reachability {\n" +
                        "    osvDir = 'osv-maven'\n" +
                        "    bomFile = 'build/cyclonedx/bom.json'\n" +
                        "    expectedOsvChecksum = '0123456789abcdef0123456789abcdef0123456789abcdef'\n" +
                        "    mappings = 'vuln-mappings.json'\n" +
                        "    pointerAnalysis = true\n" +
                        "    formats = 'json'\n" +
                        "    entryPoints.add('demo.Main#main')\n" +
                        "}\n")

        when:
        Map<String, String> dump = fixture.wiringDump()

        then:
        dump.get("task.osvDir") == "osv-maven"
        dump.get("task.bomFile") == "build/cyclonedx/bom.json"
        dump.get("task.expectedOsvChecksum") == "0123456789abcdef0123456789abcdef0123456789abcdef"
        dump.get("task.mappings") == "vuln-mappings.json"
        dump.get("task.pointerAnalysis") == "true"
        dump.get("task.cha") == "false"
        dump.get("task.formats") == "json"
        dump.get("task.entryPoints") == "[demo.Main#main]"
    }
}
