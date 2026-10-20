package org.crazyrock.callis.analysis;

import org.crazyrock.callis.engine.CallGraphPolicy;
import sootup.callgraph.CallGraph;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.callgraph.GraphBasedCallGraph;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.core.signatures.MethodSignature;
import sootup.core.views.View;
import sootup.spark.Spark;
import sootup.spark.SparkOptions;

import java.util.List;

/**
 * T33: call graph over the shared view — RTA by default
 * ({@link RapidTypeAnalysisAlgorithm}: expands a virtual call only to
 * instantiated subtypes, so dead code does not produce false-positive
 * reachability), CHA behind {@code --cha} ({@link ClassHierarchyAnalysisAlgorithm}:
 * cheaper, keeps everything the class hierarchy could reach), and — M7b (A5) —
 * the object-sensitive SPARK mode behind {@code --pointer-analysis}.
 *
 * <p>SPARK runs in on-the-fly mode: SootUp 3.0.1's {@code getCallGraph()}
 * returns a seeded graph unchanged under the default options, while
 * {@code onFlyCallGraph} grows the graph from the entry points, adding a call
 * edge only when the incremental points-to analysis justifies it. The RTA
 * seed is therefore not passed at all (in on-the-fly mode SootUp would discard
 * it).
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

    public static BuildResult build(View view, List<MethodSignature> entryPoints, CallGraphPolicy policy) {
        long started = System.currentTimeMillis();
        CallGraph graph;
        try {
            graph = switch (policy) {
                case RTA -> new RapidTypeAnalysisAlgorithm(view).initialize(entryPoints);
                case CHA -> new ClassHierarchyAnalysisAlgorithm(view).initialize(entryPoints);
                case SPARK -> spark(view, entryPoints);
            };
        } catch (OutOfMemoryError e) {
            throw new AnalysisException(SootUpSetup.memoryHint(e.getMessage()));
        }
        return new BuildResult(graph, System.currentTimeMillis() - started,
                graph.getMethodSignatures().size(), graph.getCalls().size());
    }

    /** M7b (A5): the object-sensitive mode — see the class javadoc for the 3.0.1 mode choice. */
    private static CallGraph spark(View view, List<MethodSignature> entryPoints) {
        if (entryPoints.isEmpty()) {
            return new GraphBasedCallGraph(List.of());
        }
        Spark spark = Spark.builder()
                .view(view)
                .entryPoints(entryPoints)
                .sparkOptions(SparkOptions.builder().onFlyCallGraph(true).build())
                .build();
        spark.solve();
        return spark.getCallGraph();
    }
}
