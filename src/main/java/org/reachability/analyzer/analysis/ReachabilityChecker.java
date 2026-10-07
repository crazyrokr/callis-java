package org.reachability.analyzer.analysis;

import sootup.callgraph.CallGraph;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.signatures.PackageName;
import sootup.java.core.JavaSootClass;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

import org.reachability.analyzer.osv.VulnerabilityCandidate;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * T41: the verdict model. A candidate matches at METHOD level when its
 * mapping names methods that resolve in the parsed view (reachability:
 * the resolved signature is in the call graph); otherwise it falls back
 * to ARTIFACT level (any class of the artifact's jar with a method in
 * the graph, no class-level info).
 *
 * <p>States: REACHABLE; UNREACHABLE, where {@code onClasspath} (A14)
 * flags "the artifact is in the parsed view but nothing is reachable —
 * possible reflection or dynamic dispatch"; NO_CLASS_INFO when the
 * artifact is not on the classpath at all, so nothing is known.
 */
public final class ReachabilityChecker {

    public enum VerdictStatus {
        REACHABLE,
        UNREACHABLE,
        NO_CLASS_INFO
    }

    public enum MatchLevel {
        METHOD,
        ARTIFACT
    }

    public record Verdict(VulnerabilityCandidate candidate, VerdictStatus status, MatchLevel level,
                          boolean onClasspath, List<String> path) {
        public Verdict {
            path = List.copyOf(path);
        }
    }

    private final JavaView view;
    private final CallGraph graph;
    private final List<MethodSignature> entryPoints;
    private final List<String> warnings = new ArrayList<>();

    public ReachabilityChecker(JavaView view, CallGraph graph, List<MethodSignature> entryPoints) {
        this.view = view;
        this.graph = graph;
        this.entryPoints = List.copyOf(entryPoints);
    }

    public List<Verdict> check(List<VulnerabilityCandidate> candidates,
                               Map<String, List<VulnMappingLoader.VulnTarget>> mappings,
                               ArtifactClassIndex index) {
        Set<String> candidateIds = candidates.stream()
                .map(VulnerabilityCandidate::vulnId)
                .collect(Collectors.toSet());
        for (String id : mappings.keySet()) {
            if (!candidateIds.contains(id)) {
                warnings.add("mapping entry for unknown vulnerability id: " + id);
            }
        }
        List<Verdict> verdicts = new ArrayList<>();
        for (VulnerabilityCandidate candidate : candidates) {
            verdicts.add(check(candidate, mappings.get(candidate.vulnId()), index));
        }
        return verdicts;
    }

    private Verdict check(VulnerabilityCandidate candidate, List<VulnMappingLoader.VulnTarget> targets,
                          ArtifactClassIndex index) {
        if (targets != null && !targets.isEmpty()) {
            List<MethodSignature> resolved = resolveTargets(targets);
            if (!resolved.isEmpty()) {
                MethodSignature reachable = firstReachable(resolved);
                if (reachable != null) {
                    return new Verdict(candidate, VerdictStatus.REACHABLE, MatchLevel.METHOD, true,
                            CallPathFinder.findPath(graph, entryPoints, reachable));
                }
                MethodSignature firstResolved = resolved.get(0);
                boolean onClasspath = classInView(firstResolved.getDeclClassType().getFullyQualifiedName())
                        || artifactPresent(candidate, index);
                return new Verdict(candidate, VerdictStatus.UNREACHABLE, MatchLevel.METHOD, onClasspath, List.of());
            }
            // The mapped classes are not in the parsed view: no class-level
            // info — fall back to the artifact level.
            return artifactVerdict(candidate, index);
        }
        return artifactVerdict(candidate, index);
    }

    private Verdict artifactVerdict(VulnerabilityCandidate candidate, ArtifactClassIndex index) {
        Set<String> artifactClasses = index.classesFor(candidate.componentName(), candidate.componentVersion());
        if (artifactClasses.isEmpty() || artifactClasses.stream().noneMatch(this::classInView)) {
            return new Verdict(candidate, VerdictStatus.NO_CLASS_INFO, MatchLevel.ARTIFACT, false, List.of());
        }
        MethodSignature reachable = firstGraphMethodIn(artifactClasses);
        if (reachable != null) {
            return new Verdict(candidate, VerdictStatus.REACHABLE, MatchLevel.ARTIFACT, true,
                    CallPathFinder.findPath(graph, entryPoints, reachable));
        }
        return new Verdict(candidate, VerdictStatus.UNREACHABLE, MatchLevel.ARTIFACT, true, List.of());
    }

    private List<MethodSignature> resolveTargets(List<VulnMappingLoader.VulnTarget> targets) {
        Set<MethodSignature> resolved = new TreeSet<>(Comparator.comparing(MethodSignature::toString));
        for (VulnMappingLoader.VulnTarget target : targets) {
            Optional<JavaSootClass> clazz = view.getClass(classType(target.className()));
            if (clazz.isEmpty()) {
                continue;
            }
            for (SootMethod method : clazz.get().getMethodsByName(target.methodName())) {
                if (matches(method.getSignature(), target)) {
                    resolved.add(method.getSignature());
                }
            }
        }
        return new ArrayList<>(resolved);
    }

    private static boolean matches(MethodSignature sig, VulnMappingLoader.VulnTarget target) {
        if (target.descriptor() == null) {
            return true;
        }
        return sig.getSubSignature().toString().endsWith(target.methodName() + target.descriptor());
    }

    private MethodSignature firstReachable(List<MethodSignature> ordered) {
        for (MethodSignature candidate : ordered) {
            if (graph.containsMethod(candidate)) {
                return candidate;
            }
        }
        return null;
    }

    private MethodSignature firstGraphMethodIn(Set<String> classes) {
        return graph.getMethodSignatures().stream()
                .filter(sig -> classes.contains(sig.getDeclClassType().getFullyQualifiedName()))
                // Constructors are not use of a vulnerable method: instantiating
                // the artifact is not the REACHABLE claim the verdict makes.
                .filter(sig -> !sig.getName().startsWith("<"))
                .sorted(Comparator.comparing(ReachabilityChecker::hop)
                        .thenComparing(MethodSignature::toString))
                .findFirst()
                .orElse(null);
    }

    private static String hop(MethodSignature sig) {
        return sig.getDeclClassType().getFullyQualifiedName() + "#" + sig.getName();
    }

    private boolean classInView(String className) {
        try {
            return view.getClass(classType(className)).isPresent();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Binary name (dot form) to a JavaClassType; SootUp 3.0.1 has no name-only factory. */
    private static JavaClassType classType(String className) {
        int dot = className.lastIndexOf('.');
        if (dot < 0) {
            return new JavaClassType(className, new PackageName(""));
        }
        return new JavaClassType(className.substring(dot + 1), new PackageName(className.substring(0, dot)));
    }

    private boolean artifactPresent(VulnerabilityCandidate candidate, ArtifactClassIndex index) {
        return index.classesFor(candidate.componentName(), candidate.componentVersion())
                .stream()
                .anyMatch(this::classInView);
    }

    public List<String> warnings() {
        return List.copyOf(warnings);
    }
}
