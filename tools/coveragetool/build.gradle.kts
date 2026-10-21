// The coverage gate tool (ADR 0018): evaluates JaCoCo execution data
// against the plan's gates, replacing Gradle's jacocoTestCoverageVerification
// whose ant worker in Gradle 9.x evaluates empty execution data vacuously.
plugins {
    java
    groovy
    checkstyle
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

val core = project(":core")

dependencies {
    implementation("org.jacoco:org.jacoco.core:${libs.versions.jacoco.get()}")

    testImplementation(platform(libs.groovy.bom))
    testImplementation(libs.spock.core)
    testImplementation(libs.groovy)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// The "real data" tests of CoverageGateSpec evaluate the execution data of the
// CORE test task, so the spec runs after it and reads core's outputs via the
// injected paths (its own working directory holds no coverage data).
tasks.withType<Test> {
    useJUnitPlatform()
    maxHeapSize = "1g"
    dependsOn(core.tasks.named("test"))
    systemProperty("gate.exec",
            core.layout.buildDirectory.file("jacoco/test.exec").get().asFile.absolutePath)
    systemProperty("gate.classes",
            core.layout.buildDirectory.dir("classes/java/main").get().asFile.absolutePath)
}

checkstyle {
    toolVersion = libs.versions.checkstyle.get()
    configFile = rootProject.file("config/checkstyle/checkstyle.xml")
    maxWarnings = 0
}
