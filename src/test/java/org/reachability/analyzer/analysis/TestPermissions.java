package org.reachability.analyzer.analysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * POSIX permission toggles for the unreadable-input tests. A plain Groovy
 * call of {@code Files.setPosixPermissions(Path, Set)} does not resolve to
 * the wildcard-generic overload, so the two transitions live here.
 */
public final class TestPermissions {

    private TestPermissions() {
    }

    /** Removes every permission bit (the path becomes unreadable). */
    public static void withoutRead(Path path) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("---------"));
    }

    /** Restores the permissions a temp file or directory started with. */
    public static void ownerReadWriteExecute(Path path) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"));
    }
}
