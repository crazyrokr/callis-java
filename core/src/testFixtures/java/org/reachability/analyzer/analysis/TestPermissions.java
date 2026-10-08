package org.reachability.analyzer.analysis;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

/**
 * POSIX permission toggles for the unreadable-input and unwritable-output
 * tests. A plain Groovy call of {@code Files.setPosixFilePermissions(Path,
 * Set)} does not resolve to the wildcard-generic overload, so the
 * transitions live here.
 */
public final class TestPermissions {

    private TestPermissions() {
    }

    /** Removes every permission bit (the path becomes unreadable). */
    public static void withoutRead(Path path) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("---------"));
    }

    /** Removes the owner write bit (a directory stops accepting new files). */
    public static void withoutOwnerWrite(Path path) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r-xr-xr-x"));
    }

    /** Restores the permissions a temp file or directory started with. */
    public static void ownerReadWriteExecute(Path path) throws IOException {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwxr-xr-x"));
    }
}
