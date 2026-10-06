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

// Coverage gate tool: evaluates JaCoCo execution data against the plan's gates
// (section 6). Replaces jacocoTestCoverageVerification, whose ant worker in
// Gradle 9.x evaluates empty execution data and passes vacuously (ADR 0001 amendment).
val coveragetool: SourceSet = sourceSets.create("coveragetool") {
    java.srcDir("src/coveragetool/java")
}

dependencies {
    "coveragetoolImplementation"("org.jacoco:org.jacoco.core:${libs.versions.jacoco.get()}")
    testImplementation(coveragetool.output)
    testImplementation("org.jacoco:org.jacoco.core:${libs.versions.jacoco.get()}")
}

// The specs in this task read the execution data of the main test task, so they
// must run after it (the agent writes the exec file when the test JVM exits).
val coverageGateTest by tasks.creating(Test::class) {
    description = "Runs CoverageGateSpec against the execution data of :test"
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    include("org/reachability/coveragetool/**")
    dependsOn("test")
}

tasks.named<Test>("test") {
    exclude("org/reachability/coveragetool/**")
}

val coverageGate by tasks.registering(JavaExec::class) {
    group = "verification"
    description = "Enforces the plan's coverage gates (sbom/osv/report 100% line, analysis 90% branch)"
    dependsOn("test", tasks.named("compileCoveragetoolJava"))
    classpath = coveragetool.runtimeClasspath
    mainClass = "org.reachability.coveragetool.CoverageGate"
    val gateArgs = mutableListOf(
        "--exec", layout.buildDirectory.file("jacoco/test.exec").get().asFile.absolutePath
    )
    for (dir in sourceSets.main.get().output.classesDirs) {
        gateArgs.add("--classes")
        gateArgs.add(dir.absolutePath)
    }
    gateArgs.add("--gate"); gateArgs.add("org.reachability.analyzer.sbom:LINE:1.0")
    gateArgs.add("--gate"); gateArgs.add("org.reachability.analyzer.osv:LINE:1.0")
    gateArgs.add("--gate"); gateArgs.add("org.reachability.analyzer.report:LINE:1.0")
    gateArgs.add("--gate"); gateArgs.add("org.reachability.analyzer.analysis:BRANCH:0.90")
    args(*gateArgs.toTypedArray())
}

tasks.named("check") {
    dependsOn("coverageGate", "coverageGateTest")
}
