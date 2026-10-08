package org.reachability.analyzer.engine;

/**
 * A5: which call-graph algorithm the engine builds. RTA (default) prunes to
 * the set reachable from the entry points; CHA keeps everything the class
 * hierarchy could reach. M7b adds the object-sensitive pointer-analysis mode.
 */
public enum CallGraphPolicy {
    RTA,
    CHA
}
