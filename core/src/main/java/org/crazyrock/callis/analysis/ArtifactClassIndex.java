package org.crazyrock.callis.analysis;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * T41: artifact-level matching. Maps the file name of each classpath jar
 * (artifact name, plus a version when the name carries a version suffix)
 * to the binary class names contained in the jar.
 *
 * <p>{@link #classesFor(String, String)} takes an SBOM component name
 * (with or without the {@code group:} prefix). When a version is known,
 * version-suffixed jars matching it are preferred; when none does, all
 * same-named jars are used (a wrong version is a candidate-level problem,
 * not an index-level one). Unreadable or corrupt jars warn and are skipped.
 */
public final class ArtifactClassIndex {

    /** One jar: its parsed file name, version (null when absent), and class names. */
    public record ArtifactJar(String name, String version, Set<String> classes) {
        public ArtifactJar {
            classes = Set.copyOf(classes);
        }
    }

    private final List<ArtifactJar> jars = new ArrayList<>();
    private final List<String> warnings = new ArrayList<>();

    public ArtifactClassIndex(List<Path> jarPaths) {
        for (Path jar : jarPaths) {
            indexJar(jar);
        }
    }

    private void indexJar(Path jar) {
        String file = fileName(jar);
        String stem = file.endsWith(".jar") ? file.substring(0, file.length() - 4) : file;
        int dash = stem.lastIndexOf('-');
        String name = stem;
        String version = null;
        if (dash > 0 && isVersionLike(stem.substring(dash + 1))) {
            name = stem.substring(0, dash);
            version = stem.substring(dash + 1);
        }
        Set<String> classes = readClasses(jar);
        if (classes != null) {
            jars.add(new ArtifactJar(name, version, classes));
        }
    }

    private Set<String> readClasses(Path jar) {
        try (ZipFile zip = new ZipFile(jar.toFile())) {
            Set<String> classes = new TreeSet<>();
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (!entry.isDirectory() && entryName.endsWith(".class")
                        && !entryName.startsWith("META-INF/")) {
                    classes.add(entryName.substring(0, entryName.length() - ".class".length())
                            .replace('/', '.'));
                }
            }
            return classes;
        } catch (IOException e) {
            warnings.add("cannot read artifact jar " + jar + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Binary class names of the artifact named by the SBOM component name,
     * preferring the version-suffixed jar when a version is given.
     */
    public Set<String> classesFor(String componentName, String version) {
        String bareName = bareName(componentName);
        List<ArtifactJar> matching = jars.stream()
                .filter(j -> j.name().equals(bareName))
                .toList();
        if (matching.isEmpty()) {
            return Set.of();
        }
        if (version != null && !version.isEmpty()) {
            List<ArtifactJar> exact = matching.stream()
                    .filter(j -> version.equals(j.version()))
                    .toList();
            if (!exact.isEmpty()) {
                matching = exact;
            }
        }
        Set<String> union = new HashSet<>();
        matching.forEach(j -> union.addAll(j.classes()));
        return union;
    }

    /** The artifact name part of an SBOM component name (after the group, when present). */
    private static String bareName(String componentName) {
        if (componentName == null) {
            return "";
        }
        int colon = componentName.lastIndexOf(':');
        return colon < 0 ? componentName : componentName.substring(colon + 1);
    }

    /** A version-like suffix starts with a digit and carries no other letters. */
    private static boolean isVersionLike(String part) {
        if (part.isEmpty() || !Character.isDigit(part.charAt(0))) {
            return false;
        }
        for (int i = 0; i < part.length(); i++) {
            char c = part.charAt(i);
            if (!Character.isDigit(c) && c != '.' && c != '-' && c != '_') {
                return false;
            }
        }
        return true;
    }

    private static String fileName(Path path) {
        Path name = path.getFileName();
        return name == null ? path.toString() : name.toString();
    }

    public List<String> warnings() {
        return List.copyOf(warnings);
    }
}
