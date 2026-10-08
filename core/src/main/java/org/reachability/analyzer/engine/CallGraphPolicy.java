package org.reachability.analyzer.engine;

/**
 * A5: which call-graph algorithm the engine builds. RTA (default) expands a
 * virtual call only to instantiated subtypes; CHA keeps everything the class
 * hierarchy could reach; SPARK (M7b, {@code --pointer-analysis}) is
 * object-sensitive — a call edge exists only if the points-to analysis
 * justifies it.
 */
public enum CallGraphPolicy {
    RTA,
    CHA,
    SPARK
}
