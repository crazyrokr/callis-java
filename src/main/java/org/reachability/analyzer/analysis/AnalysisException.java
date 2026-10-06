package org.reachability.analyzer.analysis;

/**
 * Analysis failure (T34): guard violations, unreadable target bytecode, or
 * memory exhaustion. The CLI maps this to exit code 3 (A8).
 */
public class AnalysisException extends RuntimeException {

    public AnalysisException(String message) {
        super(message);
    }
}
