import java.io.File
import java.util.jar.JarOutputStream
import java.util.zip.ZipEntry

// A10: the analysis engine as a library — sbom, osv, analysis, report packages
// (and the CliResult exit-code contract) that both the CLI and the Gradle/Maven
// plugins call in-process.
plugins {
    `java-library`
    `java-test-fixtures`
    groovy
    checkstyle
    jacoco
    `maven-publish`
}

group = "org.crazyrock.callis"
version = "0.1.0-SNAPSHOT"

// M7e (A10): publish core to the local Maven repository so the standalone
// maven-plugin build (maven-plugin/pom.xml) can depend on org.reachability:core.
val coreJavaComponent = components.getByName("java")

publishing {
    publications {
        create<MavenPublication>("core") {
            from(coreJavaComponent)
        }
    }
}

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
    implementation(libs.maven.artifact)
    // SootUp types (JavaView, MethodSignature, CallGraph) leak into core's
    // public API (SootUpSetup, CallGraphFactory.BuildResult), so they are api.
    api(libs.sootup.core)
    api(libs.sootup.java.core)
    api(libs.sootup.bytecode.frontend)
    api(libs.sootup.jimple.frontend)
    api(libs.sootup.callgraph)
    // SPARK (M7b) stays internal to CallGraphFactory, so implementation is enough.
    implementation(libs.sootup.spark)

    testImplementation(platform(libs.groovy.bom))
    testImplementation(libs.spock.core)
    testImplementation(libs.groovy)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Shared test utilities (TestPermissions) consumed by the cli specs.
    testFixtures(sourceSets.main.get().output)
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
        "-exclude", rootProject.file("config/spotbugs/exclude.xml").absolutePath,
        "-xml", "-output", file("build/reports/spotbugs/main.xml").absolutePath,
        "-sourcepath", file("src/main/java").absolutePath,
        "-auxclasspath", configurations.runtimeClasspath.get().files.joinToString(":") { it.absolutePath }
    )
    doFirst {
        file("build/reports/spotbugs").mkdirs()
        // Classes exist only after compilation, so the scan targets are appended at execution time.
        val dirs = sourceSets.main.get().output.classesDirs.map { it.absolutePath }
        args(*dirs.toTypedArray())
    }
}

// ---- Test fixture binaries (M7a) -------------------------------------------------
//
// No binaries are committed under fixtures/: the .class files and stublib.jar
// are generated from the committed sources before any test runs (the generated
// paths are gitignored). This replaces the M3 manual rebuild recipe.
//   mini-app: src/lib -> intermediate lib dir -> stublib.jar;
//             src/app (compiled against stublib.jar) -> classes/
//   bytecode: the committed v69 probe source compiles as-is; the v70 probe
//             is a 61-byte hand-crafted probe (v70 header + deliberately broken
//             constant pool) reproduced byte-exactly from a hex constant —
//             SootUp 3.0.1's ASM
//             parses valid v70 classes, so the zero-classes contract (A12)
//             needs the unparseable body; no javac 25 emits v70 anyway.

val miniAppDir = File(projectDir, "src/test/resources/fixtures/mini-app")
val bytecodeDir = File(projectDir, "src/test/resources/fixtures/bytecode")

val compileFixtureLib = tasks.register<JavaCompile>("compileFixtureLib") {
    // Match the original M3 fixture bytes: bare javac default debug subset (lines + source, no vars).
    options.setDebug(false)
    options.compilerArgs = listOf("-g:lines,source")
    source = fileTree(File(miniAppDir, "src/lib"))
    destinationDirectory.set(layout.buildDirectory.dir("fixtures/mini-app/lib"))
    classpath = files()
}

val stublibJar = tasks.register<Task>("stublibJar") {
    group = "build"
    description = "Jars the stublib, libpkg and jakarta fixture packages into stublib.jar"
    val libDir = File(layout.buildDirectory.asFile.get(), "fixtures/mini-app/lib")
    val target = File(miniAppDir, "stublib.jar")
    inputs.dir(libDir)
    outputs.file(target)
    dependsOn(compileFixtureLib)
    doLast {
        JarOutputStream(target.outputStream()).use { jar ->
            for (pkg in listOf("stublib", "libpkg", "jakarta")) {
                val pkgDir = File(libDir, pkg)
                pkgDir.walkTopDown().filter { it.isFile }.forEach { entry ->
                    jar.putNextEntry(ZipEntry(pkg + "/" + entry.relativeTo(pkgDir).path))
                    jar.write(entry.readBytes())
                    jar.closeEntry()
                }
            }
        }
    }
}

val compileFixtureApp = tasks.register<JavaCompile>("compileFixtureApp") {
    dependsOn(stublibJar)
    options.setDebug(false)
    options.compilerArgs = listOf("-g:lines,source")
    source = fileTree(File(miniAppDir, "src/app"))
    destinationDirectory.set(File(miniAppDir, "classes"))
    // The original M3 recipe compiled the app against the whole lib dir;
    // stublib.jar (stublib/libpkg/jakarta only) is the runtime classpath entry.
    classpath = files(File(layout.buildDirectory.asFile.get(), "fixtures/mini-app/lib"))
}

val compileFixtureBytecode = tasks.register<JavaCompile>("compileFixtureBytecode") {
    options.setDebug(false)
    options.compilerArgs = listOf("-g:lines,source")
    source = fileTree(bytecodeDir) { include("**/*.java") }
    destinationDirectory.set(layout.buildDirectory.dir("fixtures/bytecode"))
    classpath = files()
}

// The v70 probe, byte-exact: 61 hand-crafted bytes — a v70 header over a
// deliberately broken constant pool. A fully valid v70 class parses fine under
// SootUp 3.0.1's ASM, so the zero-classes contract (A12) requires the
// unparseable body; the guard's header scan still reads major 70.
// No javac 25 can emit v70 at all.
val v70ProbeHex = "cafebabe00000046000501000b546f6f4e657750726f6265" +
        "02010100106a6176612f6c616e672f4f626a65637402030001000200040000000000000000"

val generateFixtureBytecode = tasks.register<Task>("generateFixtureBytecode") {
    group = "build"
    description = "Emits the bytecode probe fixtures: v69 as compiled, v70 as the hand-crafted 61-byte probe"
    val v69Source = File(layout.buildDirectory.asFile.get(), "fixtures/bytecode/Release25Probe.class")
    val v69Target = File(bytecodeDir, "v69/Release25Probe.class")
    val v70Target = File(bytecodeDir, "v70/TooNewProbe.class")
    inputs.file(v69Source)
    outputs.file(v69Target)
    outputs.file(v70Target)
    dependsOn(compileFixtureBytecode)
    doLast {
        v69Source.copyTo(v69Target, overwrite = true)
        val bytes = ByteArray(v70ProbeHex.length / 2)
        for (i in bytes.indices) {
            bytes[i] = v70ProbeHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
        v70Target.writeBytes(bytes)
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
    maxHeapSize = "1g"
    dependsOn(compileFixtureApp, stublibJar, generateFixtureBytecode)
}

// processTestResources scans the whole resources dir the generators write into.
tasks.named("processTestResources") {
    dependsOn(compileFixtureApp, stublibJar, generateFixtureBytecode)
}

checkstyle {
    toolVersion = libs.versions.checkstyle.get()
    configFile = rootProject.file("config/checkstyle/checkstyle.xml")
    maxWarnings = 0
}

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

// The gate tool runs on the classpath of :tools:coveragetool (its classes plus
// the jacoco-core library it depends on); a project dependency carries both.
val gateTool = configurations.create("gateTool")
dependencies {
    gateTool(project(":tools:coveragetool"))
}

val coverageGate = tasks.register<JavaExec>("coverageGate") {
    group = "verification"
    description = "Enforces the plan's coverage gates (sbom/osv/report 100% line, osv/analysis 90% branch)"
    dependsOn("test")
    classpath = gateTool
    mainClass = "org.reachability.coveragetool.CoverageGate"
    val gateArgs = mutableListOf(
        "--exec", layout.buildDirectory.file("jacoco/test.exec").get().asFile.absolutePath
    )
    // SnapshotChecksum's NoSuchAlgorithmException catch is unreachable (SHA-256 is
    // a mandated JCA algorithm), so the class is kept out of the gate's denominator.
    // Its algorithm is pinned by SnapshotChecksumSpec instead.
    gateArgs.add("--exclude"); gateArgs.add("org.crazyrock.callis.osv.SnapshotChecksum")
    for (dir in sourceSets.main.get().output.classesDirs) {
        gateArgs.add("--classes")
        gateArgs.add(dir.absolutePath)
    }
    gateArgs.add("--gate"); gateArgs.add("org.crazyrock.callis.sbom:LINE:1.0")
    gateArgs.add("--gate"); gateArgs.add("org.crazyrock.callis.osv:LINE:1.0")
    gateArgs.add("--gate"); gateArgs.add("org.crazyrock.callis.osv:BRANCH:0.90")
    gateArgs.add("--gate"); gateArgs.add("org.crazyrock.callis.report:LINE:1.0")
    gateArgs.add("--gate"); gateArgs.add("org.crazyrock.callis.analysis:BRANCH:0.90")
    args(*gateArgs.toTypedArray())
}

tasks.named("check") {
    dependsOn(tasks.named("spotbugsMain"), "coverageGate",
            project(":tools:coveragetool").tasks.named("test"))
}
