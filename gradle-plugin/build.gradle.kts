// A10 (M7e): the Gradle plugin front end — applies the reachability check to
// a project's main source set and calls the :core engine in-process.
import org.gradle.api.tasks.compile.GroovyCompile

plugins {
    `java-library`
    groovy
    `java-gradle-plugin`
    checkstyle
    jacoco
}

group = "org.crazyrock.callis"
version = "0.1.0-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    api(project(":core"))

    testImplementation(platform(libs.groovy.bom))
    testImplementation(libs.spock.core)
    testImplementation(libs.groovy)
    // The Gradle distribution's Groovy module jars are stripped below, so the
    // modules the Gradle API references (groovy.ant.AntBuilder,
    // groovy.xml.XmlParser, groovy.text.Template,
    // org.apache.groovy.json.FastStringServiceFactory) come from the resolved
    // Groovy 6.0.0 instead; the core groovy artifact pulls none of them in.
    testImplementation(libs.groovy.ant)
    testImplementation(libs.groovy.json)
    testImplementation(libs.groovy.templates)
    testImplementation(libs.groovy.xml)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(gradleTestKit())
}

// The Gradle distribution embeds its own Groovy (4.0.33 in 9.8.2). The Gradle
// API injects those jars into this project's classpaths outside dependency
// resolution (they never appear in the `dependencies` report) and ahead of the
// resolved Groovy 6.0.0 jars, so their org.codehaus.groovy classes shadow
// Groovy 6's and the Spock 2.5-groovy-6.0 transform refuses to compile the
// specs. Strip the distribution's Groovy jars from the test classpaths so the
// specs compile against, and run on, the resolved Groovy 6.0.0 alone.
fun embeddedGroovyJar(file: File) =
    file.name.matches(Regex("groovy(-[a-z]+)?-\\d+(\\.\\d+)*\\.jar")) &&
        file.parentFile.parentFile?.name?.startsWith("gradle-") == true

tasks.withType<GroovyCompile>().configureEach {
    classpath = classpath.filter { !embeddedGroovyJar(it) }
}

gradlePlugin {
    plugins {
        create("reachability") {
            id = "org.crazyrock.callis"
            implementationClass = "org.reachability.gradle.ReachabilityPlugin"
            displayName = "Callis Java"
            description = "Fails the build when a vulnerability from the project's SBOM is reachable from the main source set."
        }
    }
}

// TestKit's fixture projects compile against core's generated stublib.jar;
// :gradle-plugin evaluates before :core (Gradle 9.8 subproject order is
// alphabetical), so the task references are live matching{} queries.
tasks.withType<Test> {
    useJUnitPlatform()
    maxHeapSize = "1g"
    // Same shadowing at test runtime: the in-process TestKit fixture builds
    // compile their build scripts with the test classpath's Groovy, so the
    // distribution's Groovy 4 jars must not run the Spock 6 specs either.
    classpath = classpath.filter { !embeddedGroovyJar(it) }
    dependsOn(project(":core").tasks.matching { it.name == "stublibJar" })
}

checkstyle {
    toolVersion = libs.versions.checkstyle.get()
    configFile = rootProject.file("config/checkstyle/checkstyle.xml")
    maxWarnings = 0
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}
