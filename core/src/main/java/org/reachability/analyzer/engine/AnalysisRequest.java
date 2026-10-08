package org.reachability.analyzer.engine;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A10: the domain-level inputs of {@link AnalyzerEngine}. The CLI maps its
 * options onto these; the plugins build them from the build model.
 *
 * @param appClasses           directory with the compiled application classes
 * @param classpathFile        resolved dependency classpath file (colon- or
 *                             newline-separated jar list); null = no jars
 * @param sbom                 CycloneDX bom.json of the target project
 * @param osvDir               directory with local OSV Maven records
 * @param expectedOsvChecksum  sha256 pin of the snapshot (A14); mismatch fails
 * @param mappings             optional vuln-mappings.json (A4)
 * @param policy               call-graph algorithm (A5)
 * @param entryPoints          explicit class#method entry points; wins over
 *                             auto-detection, empty = auto-detect
 * @param callbackInterfaces   additional callback interfaces (A13), via
 *                             {@link CallbackInterfaceSpecs}
 * @param expectedJavaVersion  informational hint for the bytecode guard
 */
public record AnalysisRequest(
        Path appClasses,
        Path classpathFile,
        Path sbom,
        Path osvDir,
        Optional<String> expectedOsvChecksum,
        Optional<Path> mappings,
        CallGraphPolicy policy,
        List<String> entryPoints,
        Map<String, List<String>> callbackInterfaces,
        Optional<Integer> expectedJavaVersion) {

    public AnalysisRequest {
        entryPoints = entryPoints == null ? List.of() : List.copyOf(entryPoints);
        callbackInterfaces = callbackInterfaces == null ? Map.of() : Map.copyOf(callbackInterfaces);
    }
}
