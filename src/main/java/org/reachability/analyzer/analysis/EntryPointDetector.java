package org.reachability.analyzer.analysis;

import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ArrayType;
import sootup.core.types.ClassType;
import sootup.core.types.Type;
import sootup.core.views.View;
import sootup.java.core.AnnotationUsage;
import sootup.java.core.HasAnnotation;
import sootup.java.core.JavaSootMethod;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.StreamSupport;

/**
 * T32: entry-point detection over the app classes only (A6, A13).
 *
 * <p>Detected entry points:
 * <ul>
 *   <li>{@code main(String[])} in app classes (never library mains — those
 *       live in jars, outside the app class name set);</li>
 *   <li>framework handlers by annotation, read from bytecode: Spring
 *       {@code @RestController}/{@code @Controller} handler methods
 *       ({@code org.springframework.web.bind.annotation.*}), {@code @Scheduled},
 *       {@code @KafkaListener}, {@code @RabbitListener};</li>
 *   <li>{@code doGet}/{@code doPost} of {@code @WebServlet} servlets (or
 *       {@code HttpServlet} subclasses);</li>
 *   <li>callback interfaces (bounded, A13): app classes implementing a
 *       curated framework callback list become entry points at the callback
 *       method — {@code javax/jakarta.servlet.Filter#doFilter},
 *       {@code org.quartz.Job#execute},
 *       {@code org.springframework.context.ApplicationListener#onApplicationEvent},
 *       {@code javax/jakarta.jms.MessageListener#onMessage}.
 *       Plain business interfaces are deliberately NOT entry points — that
 *       would inflate the entry set and collapse RTA precision.</li>
 * </ul>
 *
 * <p>An explicit {@code --entry-points class#method} list wins over
 * auto-detection; unresolvable entries are warned, not fatal.
 */
public final class EntryPointDetector {

    /** Curated framework callback interfaces (A13): interface name to callback method names. */
    static final Map<String, List<String>> DEFAULT_CALLBACK_INTERFACES = Map.ofEntries(
            Map.entry("javax.servlet.Filter", List.of("doFilter")),
            Map.entry("jakarta.servlet.Filter", List.of("doFilter")),
            Map.entry("org.quartz.Job", List.of("execute")),
            Map.entry("org.springframework.context.ApplicationListener", List.of("onApplicationEvent")),
            Map.entry("javax.jms.MessageListener", List.of("onMessage")),
            Map.entry("jakarta.jms.MessageListener", List.of("onMessage")));

    /** Method annotations that mark a framework handler entry point. */
    private static final Set<String> HANDLER_METHOD_ANNOTATIONS = Set.of(
            "org.springframework.scheduling.annotation.Scheduled",
            "org.springframework.kafka.annotation.KafkaListener",
            "org.springframework.amqp.rabbit.annotation.RabbitListener");

    /** Method annotations in this package mark a web handler (RequestMapping family). */
    private static final String WEB_BIND_PACKAGE = "org.springframework.web.bind.annotation.";

    private static final int MAX_SUPERCLASS_DEPTH = 16;

    private final List<String> warnings = new ArrayList<>();

    public List<String> warnings() {
        return List.copyOf(warnings);
    }

    /**
     * @param view the shared analysis view
     * @param appClassNames binary names of all classes in the app class directory
     * @param overrides explicit {@code class#method} list; when non-empty it wins over auto-detection
     * @param callbackInterfaces user additions to the curated callback list (interface to methods)
     */
    public List<MethodSignature> detect(View view, Set<String> appClassNames,
                                        List<String> overrides, Map<String, List<String>> callbackInterfaces) {
        Map<String, List<String>> callbacks = new HashMap<>();
        DEFAULT_CALLBACK_INTERFACES.forEach((iface, methods) -> callbacks.put(iface, new ArrayList<>(methods)));
        callbackInterfaces.forEach((iface, methods) -> callbacks.merge(iface, new ArrayList<>(methods),
                (existing, added) -> {
                    existing.addAll(added);
                    return existing;
                }));
        if (!overrides.isEmpty()) {
            return resolveOverrides(view, overrides);
        }

        Map<MethodSignature, Boolean> found = new LinkedHashMap<>();
        for (SootClass cls : view.getClasses().toList()) {
            if (!appClassNames.contains(cls.getName())) {
                continue;
            }
            for (SootMethod method : cls.getMethods()) {
                if (isMain(method) || isHandlerMethod(method) || isServletMethodOfWebServletClass(cls, method)) {
                    found.put(method.getSignature(), true);
                }
            }
            for (Map.Entry<String, List<String>> callback : callbacks.entrySet()) {
                if (implementsInterfaceChain(view, cls, callback.getKey())) {
                    for (String methodName : callback.getValue()) {
                        for (SootMethod method : cls.getMethodsByName(methodName)) {
                            found.put(method.getSignature(), true);
                        }
                    }
                }
            }
        }
        return new ArrayList<>(found.keySet());
    }

    /** {@code main(String[])} — the only JVM entry point we accept. */
    private static boolean isMain(SootMethod method) {
        if (!"main".equals(method.getName()) || !method.isStatic()) {
            return false;
        }
        List<Type> params = method.getParameterTypes();
        return params.size() == 1
                && params.get(0) instanceof ArrayType array
                // dimension 1 exactly: SootUp unwraps multi-dim arrays to the
                // innermost element, so without this main(String[][]) would
                // be accepted as a JVM entry (it is not)
                && array.getDimension() == 1
                && array.getBaseType() instanceof ClassType base
                && "java.lang.String".equals(base.getFullyQualifiedName());
    }

    /** A method annotated with a framework handler annotation. */
    private static boolean isHandlerMethod(SootMethod method) {
        return StreamSupport.stream(methodAnnotations(method).spliterator(), false)
                .anyMatch(usage -> {
                    String name = usage.getAnnotation().getFullyQualifiedName();
                    return HANDLER_METHOD_ANNOTATIONS.contains(name) || name.startsWith(WEB_BIND_PACKAGE);
                });
    }

    /** doGet/doPost of a @WebServlet-annotated class or an HttpServlet subclass. */
    private static boolean isServletMethodOfWebServletClass(SootClass cls, SootMethod method) {
        String name = method.getName();
        if (!"doGet".equals(name) && !"doPost".equals(name)) {
            return false;
        }
        if (StreamSupport.stream(classAnnotations(cls).spliterator(), false)
                .anyMatch(usage -> usage.getAnnotation().getFullyQualifiedName().equals(
                        "javax.servlet.annotation.WebServlet")
                        || usage.getAnnotation().getFullyQualifiedName().equals(
                        "jakarta.servlet.annotation.WebServlet"))) {
            return true;
        }
        return cls.getSuperclass().map(superclass ->
                superclass.getFullyQualifiedName().endsWith("javax.servlet.http.HttpServlet")
                        || superclass.getFullyQualifiedName().endsWith("jakarta.servlet.http.HttpServlet"))
                .orElse(false);
    }

    /** The class's own interfaces plus its superclass chain, resolved through the view. */
    private static boolean implementsInterfaceChain(View view, SootClass cls, String interfaceName) {
        Deque<SootClass> pending = new ArrayDeque<>();
        Set<String> seen = new HashSet<>();
        pending.push(cls);
        int depth = 0;
        while (!pending.isEmpty() && depth < MAX_SUPERCLASS_DEPTH) {
            SootClass current = pending.pop();
            depth++;
            if (!seen.add(current.getName())) {
                continue;
            }
            for (ClassType iface : current.getInterfaces()) {
                if (iface.getFullyQualifiedName().equals(interfaceName)) {
                    return true;
                }
                view.getClass(iface).ifPresent(pending::push);
            }
            current.getSuperclass().ifPresent(superType ->
                    view.getClass(superType).ifPresent(pending::push));
        }
        return false;
    }

    /** Explicit {@code class#method} list; unknown classes or methods are warned. */
    private List<MethodSignature> resolveOverrides(View view, List<String> overrides) {
        Map<MethodSignature, Boolean> resolved = new LinkedHashMap<>();
        Set<String> seenNames = new TreeSet<>();
        for (String override : overrides) {
            int hash = override.indexOf('#');
            if (hash <= 0 || hash == override.length() - 1) {
                warnings.add("ignoring malformed --entry-points value: " + override);
                continue;
            }
            String className = override.substring(0, hash);
            String methodName = override.substring(hash + 1);
            if (!seenNames.add(override)) {
                continue;
            }
            var clsOptional = view.getClasses().filter(c -> c.getName().equals(className)).findFirst();
            if (clsOptional.isEmpty()) {
                warnings.add("ignoring --entry-points for unknown class: " + className);
                continue;
            }
            boolean any = false;
            for (SootMethod method : clsOptional.get().getMethodsByName(methodName)) {
                resolved.put(method.getSignature(), true);
                any = true;
            }
            if (!any) {
                warnings.add("ignoring --entry-points for unknown method: " + override);
            }
        }
        return new ArrayList<>(resolved.keySet());
    }

    private static Iterable<AnnotationUsage> methodAnnotations(SootMethod method) {
        if (method instanceof JavaSootMethod javaMethod) {
            return javaMethod.getAnnotations();
        }
        if (method instanceof HasAnnotation hasAnnotation) {
            return hasAnnotation.getAnnotations();
        }
        return List.of();
    }

    private static Iterable<AnnotationUsage> classAnnotations(SootClass cls) {
        if (cls instanceof HasAnnotation hasAnnotation) {
            return hasAnnotation.getAnnotations();
        }
        return List.of();
    }
}
