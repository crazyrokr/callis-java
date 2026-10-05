import java.math.BigDecimal
import org.gradle.kotlin.dsl.withGroovyBuilder
import org.gradle.testing.jacoco.tasks.JacocoCoverageVerification

plugins {
    java
    application
    groovy
    alias(libs.plugins.shadow)
    checkstyle
    jacoco
}

group = "org.reachability"
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
    implementation(libs.jackson.databind)
    implementation(libs.picocli)
    implementation(libs.maven.artifact)
    implementation(libs.sootup.core)
    implementation(libs.sootup.java.core)
    implementation(libs.sootup.bytecode.frontend)
    implementation(libs.sootup.jimple.frontend)
    implementation(libs.sootup.callgraph)

    testImplementation(platform(libs.groovy.bom))
    testImplementation(libs.spock.core)
    testImplementation(libs.groovy)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

// SpotBugs runs as a tool (the diffplug Gradle plugin is no longer published);
// Gradle resolves the tool's transitive deps via this configuration.
val spotbugsTool = configurations.create("spotbugsTool")
dependencies {
    spotbugsTool(libs.spotbugs.tool)
}

tasks.register<JavaExec>("spotbugsMain") {
    group = "verification"
    dependsOn(tasks.named("classes"))
    classpath = spotbugsTool
    mainClass = "edu.umd.cs.findbugs.LaunchAppropriateUI"
    args(
        "-textui",
        "-effort:max",
        "-high", "-medium",
        "-exitcode",
        "-exclude", file("config/spotbugs/exclude.xml").absolutePath,
        "-xml", "-output", file("build/reports/spotbugs/main.xml").absolutePath,
        "-sourcepath", file("src/main/java").absolutePath,
        "-auxclasspath", configurations.runtimeClasspath.get().files.joinToString(":") { it.absolutePath }
    )
    doFirst {
        file("build/reports/spotbugs").mkdirs()
        // Classes exist only after compilation, so the scan targets are added at execution time.
        // Scan targets only exist after compilation, so they are appended at execution time.
        val dirs = sourceSets.main.get().output.classesDirs.map { it.absolutePath }
        args(*dirs.toTypedArray())
    }
}

tasks.named("check") {
    dependsOn(tasks.named("spotbugsMain"))
}

application {
    mainClass = "org.reachability.analyzer.ReachabilityAnalyzerCli"
}

tasks.withType<Test> {
    useJUnitPlatform()
    maxHeapSize = "1g"
}

tasks.shadowJar {
    archiveClassifier = "all"
    manifest {
        attributes["Main-Class"] = "org.reachability.analyzer.ReachabilityAnalyzerCli"
    }
    mergeServiceFiles()
    exclude("module-info.class")
    exclude("META-INF/*.sig")
    exclude("META-INF/*.SF")
    exclude("META-INF/*.DSA")
}

checkstyle {
    toolVersion = libs.versions.checkstyle.get()
    configFile = file("config/checkstyle/checkstyle.xml")
    maxWarnings = 0
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

// Coverage gates (plan section 6): osv/ and report/ at 100% line, analysis/ at >= 90% branch.
// The JaCoCo rules DSL lives in the workers jar, so the rules are configured dynamically.
tasks.withType<JacocoCoverageVerification> {
    withGroovyBuilder {
        "violationRules"({
            "rule"({
                "setElement"("PACKAGE")
                "setIncludes"(listOf("org.reachability.analyzer.osv", "org.reachability.analyzer.report"))
                "limit"({
                    "setCounter"("LINE")
                    "setValue"("COVEREDRATIO")
                    "setMinimum"(BigDecimal.ONE)
                })
            })
            "rule"({
                "setElement"("PACKAGE")
                "setIncludes"(listOf("org.reachability.analyzer.analysis"))
                "limit"({
                    "setCounter"("BRANCH")
                    "setValue"("COVEREDRATIO")
                    "setMinimum"(BigDecimal("0.90"))
                })
            })
        })
    }
}

tasks.named("check") {
    dependsOn("jacocoTestCoverageVerification")
}
