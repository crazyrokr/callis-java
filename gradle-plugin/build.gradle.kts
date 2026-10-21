// A10 (M7e): the Gradle plugin front end — applies the reachability check to
// a project's main source set and calls the :core engine in-process.
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
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    testImplementation(gradleTestKit())
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
