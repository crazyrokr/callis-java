package org.reachability.gradle

import org.gradle.api.Project
import org.gradle.api.plugins.JavaPlugin
import org.gradle.api.provider.Provider
import org.gradle.testfixtures.ProjectBuilder
import spock.lang.Specification

/**
 * M7e (A10): plugin wiring — the reachability extension and the
 * checkReachability task exist on a java project with the documented
 * defaults, the task is wired to the main source set's output and the
 * project's runtime classpath, and a project without the java plugin
 * gets an explicit error.
 */
class ReachabilityPluginSpec extends Specification {

    def "given a project with the java plugin when the reachability plugin is applied then the extension and task exist with defaults"() {
        given:
        Project project = ProjectBuilder.builder().build()
        project.plugins.apply(JavaPlugin)

        when:
        project.plugins.apply(ReachabilityPlugin)

        then:
        project.extensions.findByName("reachability") != null
        project.tasks.findByName("checkReachability") != null
        def extension = project.extensions.getByName("reachability")
        extension.getFormats().get() == "json,junitxml"
        !extension.getCha().get()
        !extension.getPointerAnalysis().get()
        extension.getEntryPoints().get().isEmpty()
        extension.getCallbackInterfaces().get().isEmpty()

        and: "the task is wired to the main source set output and the runtime classpath"
        def task = project.tasks.getByName("checkReachability")
        task.dependsOn.any { it instanceof Provider
                ? it.get().name == JavaPlugin.COMPILE_JAVA_TASK_NAME
                : it == JavaPlugin.COMPILE_JAVA_TASK_NAME }
        task.getClasspathJars().files.containsAll(project.configurations.getByName("runtimeClasspath").files)
        task.getAppClasses().get().asFile.absolutePath ==
                project.sourceSets.getByName("main").output.classesDirs.iterator().next().absolutePath
        task.getGroup() == "verification"
    }

    def "given a project without the java plugin when the reachability plugin is applied then a clear error"() {
        given:
        Project project = ProjectBuilder.builder().build()

        when:
        project.plugins.apply(ReachabilityPlugin)

        then: "Gradle wraps the plugin application failure; the cause carries the clear message"
        def e = thrown(Exception)
        e.cause instanceof IllegalStateException
        e.cause.message.contains("java plugin")
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

    def "given extension values when the task is realized then they reach the task inputs"() {
        given:
        Project project = ProjectBuilder.builder().build()
        project.plugins.apply(JavaPlugin)

        when:
        project.plugins.apply(ReachabilityPlugin)
        def extension = project.extensions.getByName("reachability")
        extension.getOsvDir().set("osv-maven")
        extension.getBomFile().set("build/cyclonedx/bom.json")
        extension.getExpectedOsvChecksum().set("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        extension.getMappings().set("vuln-mappings.json")
        extension.getPointerAnalysis().set(true)
        extension.getFormats().set("json")
        extension.getEntryPoints().add("demo.Main#main")
        def task = project.tasks.getByName("checkReachability")

        then:
        task.getOsvDir().get() == "osv-maven"
        task.getBomFile().get() == "build/cyclonedx/bom.json"
        task.getExpectedOsvChecksum().get() == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        task.getMappings().get() == "vuln-mappings.json"
        task.getPointerAnalysis().get()
        !task.getCha().get()
        task.getFormats().get() == "json"
        task.getEntryPoints().get() == ["demo.Main#main"]
    }
}
