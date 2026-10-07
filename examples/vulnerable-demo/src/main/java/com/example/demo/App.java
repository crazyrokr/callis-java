package com.example.demo;

import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.LoggerContext;

/**
 * Living integration test (T65). The pom pins log4j-core 2.14.1
 * (log4shell, GHSA-jfh8-c2jp-5v3q, and several more 2026 records), and
 * this class uses log4j-core classes directly, so the analyzer's
 * artifact-level verdict is REACHABLE and the pipeline must fail (exit 1).
 *
 * <p>Switching the pom to the fixed release 2.25.5 makes the same run
 * pass: 2.25.5 is at or beyond the fixed bound of every log4j record in
 * the OSV snapshot, so no candidate is produced (exit 0).
 */
public final class App {

    private App() {
    }

    public static void main(String[] args) {
        LoggerContext context = new LoggerContext("vulnerable-demo");
        Logger logger = context.getLogger(App.class.getName());
        logger.error("request received: {}", String.join("", args));
    }
}
