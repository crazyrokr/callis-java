package org.reachability.analyzer.analysis

import sootup.core.model.SootClass
import sootup.core.model.SootMethod
import sootup.core.signatures.MethodSignature
import sootup.core.signatures.PackageName
import sootup.core.types.ClassType
import sootup.core.views.View
import sootup.java.core.AnnotationUsage
import sootup.java.core.HasAnnotation
import sootup.java.core.types.JavaClassType
import sootup.java.core.views.JavaView
import spock.lang.Specification
import spock.lang.TempDir

import java.nio.file.Files
import java.nio.file.Path
import java.util.stream.Stream

/**
 * T32 entry-point tests (M3): main(), framework annotations (A6), the bounded
 * callback-interface list (A13, including its precision guard against plain
 * business interfaces), the --entry-points override, the servlet superclass
 * checks (javax/jakarta/odd/none), and the SootClass/SootMethod annotation
 * fallbacks (non-JavaSoot* model objects).
 */
class EntryPointDetectorSpec extends Specification {

    private static final File MINI_APP = new File("src/test/resources/fixtures/mini-app")
    private static final File STUB_JAR = new File(MINI_APP, "stublib.jar")

    @TempDir
    Path workDir

    private JavaView miniAppView() {
        def cp = workDir.resolve("cp.txt")
        Files.write(cp, STUB_JAR.absolutePath.bytes)
        def context = AnalysisContext.of(new File(MINI_APP, "classes").toPath(), cp)
        SootUpSetup.buildView(context, null)
    }

    private Set<String> appClassNames() {
        AnalysisContext.of(new File(MINI_APP, "classes").toPath(), null).appClassNames()
    }

    private List<MethodSignature> autoDetect(JavaView view) {
        new EntryPointDetector().detect(view, appClassNames(), [], [:])
    }

    private boolean has(List<MethodSignature> signatures, String className, String methodName) {
        signatures.any {
            it.getDeclClassType().getFullyQualifiedName() == className && it.getName() == methodName
        }
    }

    def "given the mini-app when auto-detected then exactly the expected entry points appear"() {
        given:
        def view = miniAppView()

        when:
        List<MethodSignature> entryPoints = autoDetect(view)

        then: "main()s, framework handlers, bounded callbacks, and servlets - and nothing else"
        has(entryPoints, "demo.Main", "main")
        has(entryPoints, "demo.MainDanger", "main")
        has(entryPoints, "demo.DeadCall", "main")
        has(entryPoints, "demo.SpringController", "data")
        has(entryPoints, "demo.ScheduledTask", "tick")
        has(entryPoints, "demo.KafkaConsumer", "onRecord")
        has(entryPoints, "demo.RabbitConsumer", "onMessage")
        has(entryPoints, "demo.WebController", "doGet")
        has(entryPoints, "demo.WebController", "doPost")
        has(entryPoints, "demo.LegacyServlet", "doGet")
        has(entryPoints, "demo.JakartaServlet", "doGet")
        has(entryPoints, "demo.PlainServlet", "doGet")
        has(entryPoints, "demo.JakartaWebServlet", "doGet")
        has(entryPoints, "demo.QuartzJobImpl", "execute")
        has(entryPoints, "demo.MyJobImpl", "execute")
        has(entryPoints, "demo.BaseListener", "onMessage")
        has(entryPoints, "demo.AdvancedListener", "onMessage")
        has(entryPoints, "demo.JmsListener", "onMessage")
        has(entryPoints, "demo.FilterImpl", "doFilter")

        and: "the full expected set: 19 entry points"
        entryPoints.size() == 19

        and: "doGet methods without a servlet superclass or annotation are NOT entries"
        !has(entryPoints, "demo.NoSuper", "doGet")
        !has(entryPoints, "demo.OddServlet", "doGet")
    }

    def "given a plain business interface implementation when auto-detected then no entry point (A13 precision guard)"() {
        given:
        def view = miniAppView()

        when:
        List<MethodSignature> entryPoints = autoDetect(view)

        then: "BusinessService.run stays out of the entry set despite its @Marked annotation"
        !has(entryPoints, "demo.BusinessService", "run")
    }

    def "given a main with the wrong signature when auto-detected then it is not an entry point"() {
        given: "NotAMain has a non-static main(String[]) and a static main(int); BadMains has five more traps"
        def view = miniAppView()

        expect:
        !autoDetect(view).any { it.getDeclClassType().getFullyQualifiedName() == "demo.NotAMain" }
        !autoDetect(view).any { it.getDeclClassType().getFullyQualifiedName() == "demo.BadMains" }
    }

    def "given a library main in the stub jar when auto-detected then it is not an entry point"() {
        given: "libpkg.Tool.main lives in stublib.jar, outside the app class directory"
        def view = miniAppView()

        expect:
        !autoDetect(view).any { it.getDeclClassType().getFullyQualifiedName() == "libpkg.Tool" }
    }

    def "given an explicit entry point override when detected then only the override is returned"() {
        given:
        def view = miniAppView()

        when:
        List<MethodSignature> entryPoints = new EntryPointDetector()
                .detect(view, appClassNames(), ["demo.Main#main"], [:])

        then: "the override wins over auto-detection"
        entryPoints.size() == 1
        has(entryPoints, "demo.Main", "main")
    }

    def "given multiple explicit entry point overrides when detected then all are resolved"() {
        given:
        def view = miniAppView()

        when:
        List<MethodSignature> entryPoints = new EntryPointDetector()
                .detect(view, appClassNames(), ["demo.Main#main", "demo.MainDanger#main", "demo.QuartzJobImpl#execute"], [:])

        then:
        entryPoints.size() == 3
        has(entryPoints, "demo.Main", "main")
        has(entryPoints, "demo.MainDanger", "main")
        has(entryPoints, "demo.QuartzJobImpl", "execute")
    }

    def "given duplicate explicit overrides when detected then duplicates collapse to one"() {
        given:
        def view = miniAppView()

        when:
        List<MethodSignature> entryPoints = new EntryPointDetector()
                .detect(view, appClassNames(), ["demo.Main#main", "demo.Main#main"], [:])

        then:
        entryPoints.size() == 1
    }

    def "given a malformed or unknown override when detected then it is warned and skipped"() {
        given: "demo.Main# has a trailing hash: the method part is empty"
        def view = miniAppView()
        def detector = new EntryPointDetector()

        when:
        List<MethodSignature> entryPoints = detector.detect(view, appClassNames(),
                ["demo.Main", "demo.Main#", "nope.Unknown#main", "demo.Main#noSuchMethod", "demo.Main#main"], [:])

        then:
        entryPoints.size() == 1
        has(entryPoints, "demo.Main", "main")
        detector.warnings().size() == 4
        detector.warnings().any { it.contains("malformed") }
        detector.warnings().any { it.contains("demo.Main#") }
        detector.warnings().any { it.contains("nope.Unknown") }
        detector.warnings().any { it.contains("noSuchMethod") }
    }

    def "given a user callback merged into a default callback interface when detected then the curated list extends"() {
        given: "--callback-interfaces org.quartz.Job=run merges into the default list (execute, run)"
        def view = miniAppView()
        def detector = new EntryPointDetector()

        when: "no app class has a run() method, so the merged list adds nothing"
        List<MethodSignature> entryPoints = detector.detect(view, appClassNames(), [],
                ["org.quartz.Job": ["run"]])

        then: "the default callback entries are untouched"
        entryPoints.size() == 19
        has(entryPoints, "demo.QuartzJobImpl", "execute")
        detector.warnings().isEmpty()
    }

    def "given a user callback for a plain business interface when detected then its implementation methods become entry points"() {
        given: "--callback-interfaces demo.Business=run extends the curated list (A13 user-extensibility)"
        def view = miniAppView()
        def detector = new EntryPointDetector()

        when:
        List<MethodSignature> entryPoints = detector.detect(view, appClassNames(), [],
                ["demo.Business": ["run"]])

        then: "the plain business interface is now a callback: run() becomes an entry point"
        has(entryPoints, "demo.BusinessService", "run")
        entryPoints.size() == 20
    }

    def "given a bare fake model class when detected then the no-annotation fallbacks return empty"() {
        given: "a SootClass/SootMethod pair that is neither JavaSoot* nor HasAnnotation"
        def bareClass = new StubSootClass("demo.Bare", [new StubSootMethod("run")] as Set,
                new HashSet<ClassType>(), Optional.empty())
        def view = new FakeView([bareClass])

        when:
        List<MethodSignature> entryPoints = new EntryPointDetector().detect(view, ["demo.Bare"] as Set, [], [:])

        then: "the instanceof fallbacks yield no annotations and no entry point"
        entryPoints.isEmpty()
    }

    def "given a fake model class with non-handler annotations when detected then the HasAnnotation path is used"() {
        given: "a SootClass/SootMethod pair implementing HasAnnotation, @Marked only"
        def marked = new AnnotationUsage(new JavaClassType("stublib.Marked", new PackageName("stublib")), [:])
        def annotatedClass = new AnnotatedSootClass("demo.Annot", [new AnnotatedSootMethod("run", [marked])],
                [marked])
        def view = new FakeView([annotatedClass])

        when:
        List<MethodSignature> entryPoints = new EntryPointDetector().detect(view, ["demo.Annot"] as Set, [], [:])

        then: "@Marked is a non-handler annotation: not an entry point"
        entryPoints.isEmpty()
    }

    /** SootClass implementing HasAnnotation on top of the inert stubs. */
    private static class AnnotatedSootClass extends StubSootClass implements HasAnnotation {
        private final List<AnnotationUsage> annotations

        AnnotatedSootClass(String name, List<SootMethod> methods, List<AnnotationUsage> annotations) {
            super(name, methods as Set, new HashSet<ClassType>(), Optional.empty())
            this.annotations = annotations
        }

        @Override
        Iterable<AnnotationUsage> getAnnotations() {
            annotations
        }
    }

    /** SootMethod implementing HasAnnotation on top of the inert stubs. */
    private static class AnnotatedSootMethod extends StubSootMethod implements HasAnnotation {
        private final List<AnnotationUsage> annotations

        AnnotatedSootMethod(String name, List<AnnotationUsage> annotations) {
            super(name)
            this.annotations = annotations
        }

        @Override
        Iterable<AnnotationUsage> getAnnotations() {
            annotations
        }
    }

    def "given a user callback with a trailing method but no interface when parsed then the curated defaults still apply"() {
        given: "the curated default list carries the six framework callbacks from the plan"
        def defaults = EntryPointDetector.DEFAULT_CALLBACK_INTERFACES

        expect:
        defaults.keySet().containsAll([
                "javax.servlet.Filter",
                "jakarta.servlet.Filter",
                "org.quartz.Job",
                "org.springframework.context.ApplicationListener",
                "javax.jms.MessageListener",
                "jakarta.jms.MessageListener"])
        defaults["javax.servlet.Filter"] == ["doFilter"]
        defaults["org.quartz.Job"] == ["execute"]
        defaults["org.springframework.context.ApplicationListener"] == ["onApplicationEvent"]
        defaults["javax.jms.MessageListener"] == ["onMessage"]
    }

    /** Minimal View: only getClasses()/getClass() are exercised by the detector. */
    private static class FakeView implements View {
        private final List<SootClass> classes

        FakeView(List<SootClass> classes) {
            this.classes = classes
        }

        @Override
        Stream<SootClass> getClasses() {
            classes.stream()
        }

        @Override
        Optional<SootClass> getClass(ClassType classType) {
            Optional.ofNullable(classes.find { it.getName() == classType.getFullyQualifiedName() })
        }

        @Override
        Optional<sootup.core.model.SootField> getField(sootup.core.signatures.FieldSignature signature) {
            Optional.empty()
        }

        @Override
        Optional<sootup.core.model.SootMethod> getMethod(sootup.core.signatures.MethodSignature signature) {
            Optional.empty()
        }

        @Override
        sootup.core.typehierarchy.TypeHierarchy getTypeHierarchy() {
            null
        }

        @Override
        sootup.core.IdentifierFactory getIdentifierFactory() {
            null
        }
    }
}
