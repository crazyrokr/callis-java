package org.reachability.analyzer.analysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * A12 startup guard.
 *
 * <p>SootUp 3.0.1 (ASM 9.10.1) parses class files up to major version 69
 * (Java 25). For newer versions it silently returns zero classes, so a target
 * built with unsupported bytecode would pass with no findings — a false
 * negative. The guard scans the app class directory for the highest class
 * file major version and fails the run ({@link AnalysisException}, CLI exit 3)
 * when it exceeds the ceiling.
 *
 * <p>The class file header is read raw (magic {@code CAFEBABE}, minor, major)
 * so the guard works without SootUp; a file without a valid header reports
 * major 0 and is left to the zero-classes check in {@link SootUpSetup}.
 */
public final class BytecodeVersionGuard {

    /** Highest class file major version SootUp 3.0.1 parses (69 = Java 25). */
    public static final int SUPPORTED_MAX_MAJOR = 69;

    private static final int MAGIC = 0xCAFEBABE;

    private BytecodeVersionGuard() {
    }

    /** Result of scanning one class directory (defensive copies: the scan lists never leak). */
    public record Scan(List<Path> classFiles, int maxMajor, List<Path> aboveCeiling) {
        public Scan {
            classFiles = List.copyOf(classFiles);
            aboveCeiling = List.copyOf(aboveCeiling);
        }
    }

    /** Reads the class files under {@code classDir} (recursively, {@code *.class}). */
    public static Scan scan(Path classDir) {
        List<Path> classFiles = new ArrayList<>();
        List<Path> aboveCeiling = new ArrayList<>();
        int maxMajor = 0;
        if (Files.isDirectory(classDir)) {
            try (var files = Files.walk(classDir)) {
                for (Path file : files.filter(f -> fileName(f).endsWith(".class")).toList()) {
                    classFiles.add(file);
                    int major = classFileMajorVersion(file);
                    if (major > maxMajor) {
                        maxMajor = major;
                    }
                    if (major > SUPPORTED_MAX_MAJOR) {
                        aboveCeiling.add(file);
                    }
                }
            } catch (IOException e) {
                throw new AnalysisException("cannot scan app class directory " + classDir + ": " + e.getMessage());
            }
        }
        return new Scan(classFiles, maxMajor, aboveCeiling);
    }

    /**
     * Fails with an {@link AnalysisException} when any class file exceeds the
     * supported ceiling. The message names the offending files, the detected
     * version, and the fix (rebuild with an older {@code --release}).
     */
    public static void requireSupported(Scan scan, Integer expectedJavaVersion) {
        if (scan.aboveCeiling().isEmpty()) {
            return;
        }
        StringBuilder offending = new StringBuilder();
        for (int i = 0; i < Math.min(scan.aboveCeiling().size(), 5); i++) {
            if (i > 0) {
                offending.append(", ");
            }
            offending.append(scan.aboveCeiling().get(i));
        }
        if (scan.aboveCeiling().size() > 5) {
            offending.append(" (and ").append(scan.aboveCeiling().size() - 5).append(" more)");
        }
        throw new AnalysisException("target bytecode exceeds the supported ceiling: "
                + scan.aboveCeiling().size() + " class file(s) at major version "
                + scan.maxMajor() + " > " + SUPPORTED_MAX_MAJOR + " (Java 25) — SootUp 3.0.1 would "
                + "silently parse them to zero classes. Offending file(s): " + offending
                + (expectedJavaVersion == null ? "" : " (expected Java " + expectedJavaVersion + ")")
                + ". Rebuild the target with an older --release or upgrade the analyzer.");
    }

    /** File name of a path; empty when {@code getFileName()} is null (the filesystem root). */
    private static String fileName(Path path) {
        Path name = path.getFileName();
        return name == null ? "" : name.toString();
    }

    /** Major version of one class file; 0 when the header is missing or unreadable. */
    static int classFileMajorVersion(Path file) {
        byte[] header;
        try {
            header = Files.readAllBytes(file);
        } catch (IOException e) {
            return 0;
        }
        if (header.length < 8) {
            return 0;
        }
        int magic = ((header[0] & 0xFF) << 24) | ((header[1] & 0xFF) << 16)
                | ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
        if (magic != MAGIC) {
            return 0;
        }
        return ((header[6] & 0xFF) << 8) | (header[7] & 0xFF);
    }
}
