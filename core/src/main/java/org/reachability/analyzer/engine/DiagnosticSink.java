package org.reachability.analyzer.engine;

import java.io.PrintStream;

/**
 * The engine's console channel. The CLI plugs in the real stdout/stderr; the
 * plugins plug in a collecting sink so they can surface the same diagnostics
 * without touching the console.
 */
public interface DiagnosticSink {

    void out(String line);

    void err(String line);

    static DiagnosticSink of(PrintStream out, PrintStream err) {
        return new DiagnosticSink() {
            @Override
            public void out(String line) {
                out.println(line);
            }

            @Override
            public void err(String line) {
                err.println(line);
            }
        };
    }
}
