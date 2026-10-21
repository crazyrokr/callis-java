package org.crazyrock.callis.analysis;

import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;

/**
 * T31: builds the single {@link JavaView} over the app class directory and the
 * resolved jars — one colon-joined classpath string covers both (A1).
 *
 * <p>Before building the view, the A12 guard runs: class files beyond the
 * supported bytecode ceiling fail the run, and a non-empty app class
 * directory that SootUp parses to zero classes fails loudly (both
 * {@link AnalysisException}, CLI exit 3) instead of passing silently.
 *
 * <p>All SootUp types are confined to this class and
 * {@link CallGraphFactory}, so a SootUp upgrade is a small diff (ADR 0002, A1).
 */
public final class SootUpSetup {

    private SootUpSetup() {
    }

    public static JavaView buildView(AnalysisContext context, Integer expectedJavaVersion) {
        BytecodeVersionGuard.requireSupported(context.scan(), expectedJavaVersion);

        JavaView view;
        try {
            AnalysisInputLocation location =
                    new JavaClassPathAnalysisInputLocation(context.classpathString());
            view = new JavaView(location);
        } catch (OutOfMemoryError e) {
            throw new AnalysisException(memoryHint(e.getMessage()));
        }

        if (!context.scan().classFiles().isEmpty() && view.getClasses().findFirst().isEmpty()) {
            throw new AnalysisException("app class directory '" + context.appClassesDir()
                    + "' contains " + context.scan().classFiles().size()
                    + " class file(s) but SootUp parsed zero classes"
                    + (context.maxBytecodeMajor() > 0
                        ? " (max class file major " + context.maxBytecodeMajor() + ")"
                        : "")
                    + " — the bytecode is corrupt or beyond the supported ceiling; refusing to continue");
        }
        return view;
    }

    /** T34: memory-guard error message with the -Xmx guidance. */
    static String memoryHint(String cause) {
        return "out of memory while building the call graph"
                + (cause == null ? "" : " (" + cause + ")")
                + " — re-run with a larger heap (e.g. -Xmx4g) or narrow the classpath scope";
    }
}
