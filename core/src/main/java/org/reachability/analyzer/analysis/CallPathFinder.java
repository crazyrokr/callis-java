package org.reachability.analyzer.analysis;

import sootup.callgraph.CallGraph;
import sootup.core.signatures.MethodSignature;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * T43: extracts one shortest call path from any entry point to a target
 * method. Multi-source BFS over the reachability-reduced call graph:
 * sources are deduplicated and sorted lexicographically, successors are
 * expanded in the graph's sorted call order (line-number order per
 * method), so the first path found is deterministic — the lexicographic
 * first source, then the first line.
 */
public final class CallPathFinder {

    private CallPathFinder() {
    }

    /**
     * @return the path as {@code class#method} hops (entry first, target
     *         last), or an empty list when no source is in the graph, the
     *         target is not in the graph, or no source reaches the target
     */
    public static List<String> findPath(CallGraph graph, List<MethodSignature> sources, MethodSignature target) {
        if (sources.isEmpty() || target == null || !graph.containsMethod(target)) {
            return List.of();
        }
        // Sort by the user-visible class#method hop, not by MethodSignature.toString():
        // the latter embeds the class in "<class: sig>" form, where ':' sorts after
        // digits, so VulnCaller2 would come before VulnCaller.
        List<MethodSignature> ordered = sources.stream()
                .filter(graph::containsMethod)
                .distinct()
                .sorted(Comparator.comparing(CallPathFinder::hop).thenComparing(MethodSignature::toString))
                .toList();
        if (ordered.isEmpty()) {
            return List.of();
        }
        for (MethodSignature source : ordered) {
            if (source.equals(target)) {
                return List.of(hop(target));
            }
        }
        Map<MethodSignature, MethodSignature> predecessor = new HashMap<>();
        Set<MethodSignature> queued = new HashSet<>(ordered);
        Deque<MethodSignature> queue = new ArrayDeque<>(ordered);
        MethodSignature found = null;
        while (!queue.isEmpty() && found == null) {
            MethodSignature current = queue.poll();
            for (CallGraph.Call call : graph.sortedCallsFrom(current)) {
                MethodSignature next = call.targetMethodSignature();
                if (next.equals(target)) {
                    found = next;
                    predecessor.putIfAbsent(next, current);
                    break;
                }
                if (queued.add(next)) {
                    predecessor.put(next, current);
                    queue.add(next);
                }
            }
        }
        if (found == null) {
            return List.of();
        }
        List<MethodSignature> chain = new ArrayList<>();
        MethodSignature cursor = found;
        while (true) {
            chain.add(cursor);
            MethodSignature from = predecessor.get(cursor);
            if (from == null) {
                break;
            }
            cursor = from;
        }
        Collections.reverse(chain);
        return chain.stream().map(CallPathFinder::hop).toList();
    }

    private static String hop(MethodSignature sig) {
        return sig.getDeclClassType().getFullyQualifiedName() + "#" + sig.getName();
    }
}
