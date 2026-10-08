package org.reachability.analyzer.engine;

import org.reachability.analyzer.report.AnalysisReport;

import java.util.Optional;

/**
 * The engine's outcome: the A8 exit code (0 = no reachable vulnerability,
 * 1 = at least one REACHABLE, 2 = usage error, 3 = analysis failure) and the
 * report model when a run produced one (absent on zero-candidate runs and on
 * failures before report generation).
 */
public record AnalysisResult(int exitCode, Optional<AnalysisReport> report) {
}
