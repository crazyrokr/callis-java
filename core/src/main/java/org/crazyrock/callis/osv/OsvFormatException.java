package org.crazyrock.callis.osv;

/** A record file is not a well-formed OSV record. The repository skips it. */
public final class OsvFormatException extends RuntimeException {

    public OsvFormatException(String message) {
        super(message);
    }
}
