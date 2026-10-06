package org.reachability.analyzer.analysis;

import sootup.callgraph.CallGraph;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.core.signatures.MethodSignature;
import sootup.core.views.View;

import java.util.List;

/**
 * T33: call graph over the shared view — RTA by default
 * ({@link RapidTypeAnalysisAlgorithm}: prunes to the set reachable from the
 * entry points, so dead code does not produce false-positive reachability),
 * CHA behind {@code --cha} ({@link ClassHierarchyAnalysisAlgorithm}: cheaper,
 * keeps everything the class hierarchy could reach).
 *
 * <p>Build size and time are reported in the {@link BuildResult} (the CLI
 * prints them at {@code --verbose}); an {@code OutOfMemoryError} becomes an
 * {@link AnalysisException} with -Xmx guidance (T34).
 */
public final class CallGraphFactory {

    /** The built graph with its size and build time. */
    public record BuildResult(CallGraph graph, long buildMillis, int nodeCount, int edgeCount) {
    }

    private CallGraphFactory() {
    }

    public static BuildResult build(View view, List<MethodSignature> entryPoints, boolean cha) {
        long started = System.currentTimeMillis();
        CallGraph graph;
        try {
            if (cha) {
                graph = new ClassHierarchyAnalysisAlgorithm(view).initialize(entryPoints);
            } else {
                graph = new RapidTypeAnalysisAlgorithm(view).initialize(entryPoints);
            }
        } catch (OutOfMemoryError e) {
            throw new AnalysisException(SootUpSetup.memoryHint(e.getMessage()));
        }
        return new BuildResult(graph, System.currentTimeMillis() - started,
                graph.getMethodSignatures().size(), graph.getCalls().size());
    }
}
