package org.reachability.analyzer.analysis;

import java.io.IOException;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * T31/T34: the analysis input — the app class directory, the resolved jar list
 * from the classpath file, the bytecode scan, and the collected warnings.
 *
 * <p>One colon-joined classpath string (app classes + jars) covers everything,
 * per A1. Jars listed in the classpath file but unreadable become warnings
 * (T34: skip and continue, never fail the whole run for one missing jar).
 */
public final class AnalysisContext {

    private final Path appClassesDir;
    private final List<Path> jars = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();
    private final BytecodeVersionGuard.Scan scan;

    private AnalysisContext(Path appClassesDir, BytecodeVersionGuard.Scan scan) {
        this.appClassesDir = appClassesDir;
        this.scan = scan;
    }

    /**
     * @throws IOException when the app class directory does not exist (the CLI
     *         maps this to exit 2 — a broken invocation, not an analysis failure)
     */
    public static AnalysisContext of(Path appClassesDir, Path classpathFile) throws IOException {
        if (!Files.isDirectory(appClassesDir)) {
            throw new IOException("app classes directory does not exist: " + appClassesDir);
        }
        AnalysisContext context = new AnalysisContext(appClassesDir, BytecodeVersionGuard.scan(appClassesDir));
        if (classpathFile == null) {
            return context;
        }
        if (!Files.isRegularFile(classpathFile)) {
            context.warnings.add("classpath file does not exist, analyzing without jars: " + classpathFile);
            return context;
        }
        for (String line : Files.readAllLines(classpathFile)) {
            for (String entry : line.split(":")) {
                String jarName = entry.trim();
                if (jarName.isEmpty()) {
                    continue;
                }
                Path jar = Path.of(jarName);
                if (Files.isRegularFile(jar) && Files.isReadable(jar)) {
                    context.jars.add(jar);
                } else {
                    context.warnings.add("jar listed in classpath file but unreadable: " + jar);
                }
            }
        }
        return context;
    }

    /** The single classpath string handed to SootUp (app classes + jars). */
    public String classpathString() {
        StringBuilder classpath = new StringBuilder(appClassesDir.toString());
        for (Path jar : jars) {
            classpath.append(File.pathSeparatorChar).append(jar);
        }
        return classpath.toString();
    }

    /** Binary names (dot form) of all class files in the app class directory. */
    public Set<String> appClassNames() {
        TreeSet<String> names = new TreeSet<>();
        for (Path file : scan.classFiles()) {
            String relative = appClassesDir.relativize(file).toString().replace(File.separatorChar, '/');
            names.add(relative.substring(0, relative.length() - ".class".length())
                    .replace('/', '.').replace('$', '.'));
        }
        return names;
    }

    public Path appClassesDir() {
        return appClassesDir;
    }

    public List<Path> jars() {
        return List.copyOf(jars);
    }

    public List<String> warnings() {
        return List.copyOf(warnings);
    }

    public BytecodeVersionGuard.Scan scan() {
        return scan;
    }

    /** Highest class file major version found in the app classes (0 when none). */
    public int maxBytecodeMajor() {
        return scan.maxMajor();
    }
}
