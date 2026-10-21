package org.crazyrock.callis.osv;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.stream.Stream;

/**
 * Deterministic content hash of an OSV snapshot directory (A14).
 *
 * <p>Algorithm: over all {@code *.json} files directly under the directory,
 * sorted by file name, concatenate {@code name + ":" + hexSha256(file) + "\n"}
 * and take the sha256 of the concatenation. Independent of file creation
 * order; an empty directory hashes as the sha256 of empty input. The M6
 * {@code download-osv.sh} pin file carries the same value.
 */
public final class SnapshotChecksum {

    private SnapshotChecksum() {
    }

    public static String sha256OfDirectory(Path directory) throws IOException {
        if (!Files.isDirectory(directory)) {
            throw new IOException("not a directory: " + directory);
        }
        StringBuilder content = new StringBuilder();
        try (Stream<Path> files = Files.list(directory)) {
            for (Path file : files
                    .filter(f -> fileName(f).endsWith(".json"))
                    .sorted(Comparator.comparing(SnapshotChecksum::fileName))
                    .toList()) {
                content.append(fileName(file))
                        .append(':')
                        .append(sha256Hex(Files.readAllBytes(file)))
                        .append('\n');
            }
        }
        return sha256Hex(content.toString().getBytes(StandardCharsets.UTF_8));
    }

    /** Path.getFileName() is null for the filesystem root, which a listing never yields. */
    private static String fileName(Path file) {
        Path name = file.getFileName();
        return name == null ? "" : name.toString();
    }

    static String sha256Hex(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
