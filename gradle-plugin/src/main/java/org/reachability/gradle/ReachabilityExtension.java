package org.reachability.gradle;

import org.gradle.api.provider.ListProperty;
import org.gradle.api.provider.Property;

/**
 * A10 (M7e): the {@code reachability { ... }} extension. Paths are relative
 * to the project unless absolute; the defaults are the safe ones (RTA
 * policy, json+junitxml reports, no overrides).
 */
public abstract class ReachabilityExtension {

    /** The target's SBOM (CycloneDX or SPDX 2.x JSON). Required. */
    public abstract Property<String> getBomFile();

    /** Directory with the local OSV Maven records. Required. */
    public abstract Property<String> getOsvDir();

    /** sha256 pin of the OSV snapshot (A14); mismatch fails the task. */
    public abstract Property<String> getExpectedOsvChecksum();

    /** Optional vuln-mappings.json for class/method-level precision (A4). */
    public abstract Property<String> getMappings();

    /** Explicit class#method entry points; empty = auto-detect. */
    public abstract ListProperty<String> getEntryPoints();

    /** Additional callback interfaces (class#method, A13); extends the curated list. */
    public abstract ListProperty<String> getCallbackInterfaces();

    /** Build the call graph with CHA instead of RTA (mutually exclusive with pointerAnalysis). */
    public abstract Property<Boolean> getCha();

    /** Build the call graph with SPARK object-sensitive pointer analysis (M7b). */
    public abstract Property<Boolean> getPointerAnalysis();

    /** Comma-separated report formats: json, junitxml, sarif. */
    public abstract Property<String> getFormats();

    /** Max heap of the forked analysis worker (M9); the daemon's heap no longer bounds the graph. */
    public abstract Property<String> getMaxHeapSize();
}
