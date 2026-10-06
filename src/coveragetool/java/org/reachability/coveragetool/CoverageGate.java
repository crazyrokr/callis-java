package org.reachability.coveragetool;

import org.jacoco.core.analysis.Analyzer;
import org.jacoco.core.analysis.CoverageBuilder;
import org.jacoco.core.analysis.IBundleCoverage;
import org.jacoco.core.analysis.ICounter;
import org.jacoco.core.analysis.ICoverageNode;
import org.jacoco.core.data.ExecutionDataStore;
import org.jacoco.core.tools.ExecFileLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Enforces the coverage gates of the implementation plan (section 6) by
 * evaluating JaCoCo execution data against per-package line/branch minimums.
 *
 * <p>Replaces the Gradle {@code jacocoTestCoverageVerification} task, whose
 * ant-based worker evaluates empty execution data in Gradle 9.x and therefore
 * passes vacuously (see ADR 0001 amendment).
 *
 * <p>Exit codes: 0 = all gates pass, 1 = at least one gate violated,
 * 2 = usage or I/O error.
 */
public final class CoverageGate {

    private CoverageGate() {
    }

    public static void main(String[] args) {
        System.exit(exitCode(args));
    }

    /** 0 = all gates pass, 1 = violated, 2 = usage or I/O error. */
    static int exitCode(String[] args) {
        try {
            return run(parse(args));
        } catch (IllegalArgumentException | IOException e) {
            System.err.println("ERROR: " + e.getMessage());
            return 2;
        }
    }

    /** Result of evaluating the gates; exitCode is 0 or 1. */
    public record GateResult(int exitCode, String report) {
    }

    static int run(Parsed parsed) throws IOException {
        ExecutionDataStore store = loadExecutionData(parsed.exec());
        return evaluate(store, parsed.classDirs(), parsed.gates()).exitCode();
    }

    public static GateResult evaluate(ExecutionDataStore store,
                                      Iterable<Path> classDirs, List<Gate> gates) {
        CoverageBuilder builder = new CoverageBuilder();
        for (Path dir : classDirs) {
            if (!Files.isDirectory(dir)) {
                continue;
            }
            try {
                new Analyzer(store, builder).analyzeAll(dir.toFile());
            } catch (IOException e) {
                throw new IllegalStateException("cannot analyze " + dir, e);
            }
        }
        IBundleCoverage bundle = builder.getBundle("coverage-gate");

        List<String> lines = new ArrayList<>();
        for (Path dir : classDirs) {
            if (!Files.isDirectory(dir)) {
                lines.add(String.format("%-40s directory missing - skipped", dir));
            }
        }
        boolean violated = false;
        for (Gate gate : gates) {
            ICoverageNode packageNode = findPackage(bundle, gate.packageName());
            if (packageNode == null) {
                lines.add(String.format("%-40s no classes in main code - skipped", gate.packageName()));
                continue;
            }
            ICounter counter = "BRANCH".equals(gate.counter())
                    ? packageNode.getBranchCounter()
                    : packageNode.getLineCounter();
            int total = counter.getTotalCount();
            int covered = counter.getCoveredCount();
            double ratio = total == 0 ? 1.0 : (double) covered / total;
            boolean ok = total == 0 || ratio + 1e-9 >= gate.minimum();
            lines.add(String.format("%-40s %s %d/%d = %.4f (min %.4f) -> %s",
                    gate.packageName(), gate.counter(), covered, total, ratio,
                    gate.minimum(), ok ? "ok" : "VIOLATION"));
            violated |= !ok;
        }
        String report = String.join(System.lineSeparator(), lines);
        System.out.println(report);
        return new GateResult(violated ? 1 : 0, report);
    }

    private static ICoverageNode findPackage(IBundleCoverage bundle, String dottedName) {
        String slashed = dottedName.replace('.', '/');
        return bundle.getPackages().stream()
                .filter(p -> p.getName().equals(slashed))
                .findFirst()
                .orElse(null);
    }

    /** One gate: dotted package name, LINE or BRANCH, minimum covered ratio. */
    public record Gate(String packageName, String counter, double minimum) {
    }

    /** Parsed command line: exec file, class dirs, gates. */
    public record Parsed(Path exec, List<Path> classDirs, List<Gate> gates) {
    }

    static Parsed parse(String[] args) {
        Path exec = null;
        List<Path> classDirs = new ArrayList<>();
        List<Gate> gates = new ArrayList<>();
        int i = 0;
        while (i < args.length) {
            switch (args[i]) {
                case "--exec" -> {
                    exec = Path.of(requireNext(args, i, "--exec"));
                    i += 2;
                }
                case "--classes" -> {
                    classDirs.add(Path.of(requireNext(args, i, "--classes")));
                    i += 2;
                }
                case "--gate" -> {
                    gates.add(parseGate(requireNext(args, i, "--gate")));
                    i += 2;
                }
                default -> throw new IllegalArgumentException("unknown option: " + args[i]);
            }
        }
        if (exec == null) {
            throw new IllegalArgumentException("--exec <file> is required");
        }
        if (classDirs.isEmpty()) {
            throw new IllegalArgumentException("at least one --classes <dir> is required");
        }
        if (gates.isEmpty()) {
            throw new IllegalArgumentException("at least one --gate <pkg:LINE|BRANCH:min> is required");
        }
        return new Parsed(exec, classDirs, gates);
    }

    private static String requireNext(String[] args, int i, String option) {
        if (i + 1 >= args.length) {
            throw new IllegalArgumentException(option + " requires a value");
        }
        return args[i + 1];
    }

    /** Format: {@code org.pkg:LINE:1.0} or {@code org.pkg:BRANCH:0.9}. */
    static Gate parseGate(String spec) {
        String[] parts = spec.split(":");
        if (parts.length != 3) {
            throw new IllegalArgumentException(
                    "malformed gate '" + spec + "' (expected <pkg>:<LINE|BRANCH>:<min>)");
        }
        if (!"LINE".equals(parts[1]) && !"BRANCH".equals(parts[1])) {
            throw new IllegalArgumentException("gate counter must be LINE or BRANCH: " + spec);
        }
        double min;
        try {
            min = Double.parseDouble(parts[2]);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("gate minimum must be a number: " + spec);
        }
        if (parts[0].isEmpty() || min < 0 || min > 1) {
            throw new IllegalArgumentException("gate must have a package and a min in [0,1]: " + spec);
        }
        return new Gate(parts[0], parts[1], min);
    }

    static ExecutionDataStore loadExecutionData(Path execFile) throws IOException {
        if (!Files.isRegularFile(execFile)) {
            throw new IOException("execution data file does not exist: " + execFile);
        }
        ExecFileLoader loader = new ExecFileLoader();
        try (var in = Files.newInputStream(execFile)) {
            loader.load(in);
        }
        return loader.getExecutionDataStore();
    }
}
