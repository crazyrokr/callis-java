# ADR 0006 — A5: RTA default, `--cha` flag, `--pointer-analysis` flag (SPARK)

- **Status:** accepted (2026-10-05); amended: M3 verification (2026-10-06), M4 verification (2026-10-07), M7b (2026-10-09)
- **Related:** ADR 0001 (index), ADR 0002 (SootUp backend), ADR 0007 (entry points), ADR 0017 (benchmark baseline)

## Decision

RTA (`RapidTypeAnalysisAlgorithm`) prunes to the set reachable from entry points →
fewer false positives from dead code. SootUp 3.0.1's RTA is already
allocation-sensitive (a virtual call expands only to subtypes instantiated by a
`new` expression), so its remaining false-positive mode is a class that is
instantiated somewhere but never dispatched at a call site. CHA
(`ClassHierarchyAnalysisAlgorithm`) keeps everything the hierarchy could reach —
the least precise mode, a comparison tool rather than a gate. SPARK
(`org.soot-oss:sootup.spark`, behind `--pointer-analysis`, M7b) is the
object-sensitive pointer-analysis mode: its call graph grows on-the-fly from the
entry points and a call edge exists only when the incremental points-to analysis
justifies the dispatch, pruning that instantiated-but-never-dispatched class
(`PointerDemo2` fixture: RTA/CHA keep the edge, SPARK prunes it).

Deviation from the plan text: the plan said "Heros IFDS"; SootUp 3.0.1 ships
SPARK as the maintained implementation of exactly that capability
(`sootup.analysis.interprocedural` is the raw IFDS framework — no ready-made
Heros exists) → SPARK.

SootUp 3.0.1 API facts that shaped the implementation (empirical, verified
against the resolved jars and the v3.0.1 sources): under the default
`SparkOptions`, `Spark.getCallGraph()` returns the seed graph **unchanged**
(`solve()` only builds the PAGs), so an "RTA seed + refinement" recipe is a
no-op; refinement exists only in `onFlyCallGraph(true)` mode, where the Solver
discards any pre-built graph and grows a `GraphBasedCallGraph` from the entry
points. ⇒ the SPARK mode runs on-the-fly **without a seed** (an RTA seed
passed in that mode would be discarded anyway).

## Amendments

- **2026-10-06 (M3 verification):** the call graph is RTA by default (prunes
  to what the entry points reach — the plan's false-positive pin: a dead
  virtual call to a never-instantiated implementation is pruned under RTA
  but kept under `--cha`, both pinned), built via
  `sootup.callgraph.{RapidTypeAnalysis,ClassHierarchy}AnalysisAlgorithm` on
  the shared `JavaView` (A1). `--dry-run-graph` prints the detected entries
  (`-v`) and the graph node/call counts + build time (M3 acceptance); an
  app directory with **no detectable entry points is exit 3** (nothing to
  analyze is a broken invocation, not a clean pass). `OutOfMemoryError`
  during view/graph build becomes an `AnalysisException` with `-Xmx4g`
  guidance; classpath-file entries that are missing/unreadable become
  warnings (T34 skip-and-continue); a non-readable class directory fails the
  scan (`cannot scan` → exit 3).

- **2026-10-07 (M4 verification):** path extraction (T43) is a multi-source
  BFS over the reachability-reduced graph — one shortest path per
  candidate, hops as `class#method`. Determinism: sources are sorted by the
  **user-visible `class#method` hop string**, not by
  `MethodSignature.toString()`: the latter renders
  `<demo.VulnCaller: void main(...)>`, where the `:` sorts after digits, so
  `VulnCaller2` would precede `VulnCaller` (pinned: two equal-distance
  callers yield exactly the lexicographic-first path, repeat-call
  identical; a closer caller beats a farther one).

- **2026-10-09 (M7b):** SPARK pointer-analysis mode (A5 amended in place).
  * Dependency: `org.soot-oss:sootup.spark` 3.0.1 (same pin as the rest of
    SootUp) as `implementation` in `core` — SPARK stays internal to
    `CallGraphFactory`, nothing leaks into the API.
  * `CallGraphFactory.build(view, entryPoints, boolean cha)` →
    `build(view, entryPoints, CallGraphPolicy policy)` (enum RTA/CHA/SPARK,
    new `engine/CallGraphPolicy`); the SPARK branch runs
    `Spark.builder().view(...).entryPoints(...).sparkOptions(SparkOptions
    .builder().onFlyCallGraph(true).build()).build()` → `solve()` →
    `getCallGraph()`. Two empirical discoveries reshaped the plan's recipe:
    (1) SootUp 3.0.1's RTA is already allocation-sensitive, so the
    plan's "RTA false positive at a pure allocation site" pin does not hold
    — the true RTA↔SPARK discriminator is an instantiated-but-never-dispatched
    class; (2) `defaultOptions() + callGraph(seed)` is a no-op refinement
    (`getCallGraph()` returns the seed unchanged; the Solver refines only in
    `onFlyCallGraph` mode, where it discards any seed) — hence OTF without a
    seed. Both recorded above in the amended A5.
  * CLI: `--pointer-analysis`, mutually exclusive with `--cha` (both → exit 2
    "mutually exclusive"); report metadata `callGraphBuilder` = `SPARK`;
    `--dry-run-graph` names the policy.
  * Fixtures: `demo.PIface`, `demo.SafeImpl`, `demo.DangerImpl`,
    `demo.PointerDemo` (allocation-only dispatch — already pruned by 3.0.1's
    RTA, pinned as such) and `demo.PointerDemo2` (the discriminator:
    `new DangerImpl()` by assignment, never dispatched — RTA/CHA keep the
    `danger` edge, SPARK prunes it while keeping the executed `DangerImpl#
    <init>` and the true-positive chain intact). Fixture app classes 49 →
    54; entry points 21 → 23 (pinned).
  * Tests written first, then implementation: `CallGraphFactorySpec` 8 → 15
    (the SPARK suite pins the subset property — SPARK nodes and (source,
    target) edge pairs are a strict subset of RTA's — plus the true
    negative, the preserved true positive, and independent multi-entry
    exploration); `CliSpec` 40 → 43; `AnalyzerEngineSpec` 9 → 10 (296 → 304); the
    `CallPathFinderSpec`/`ReachabilityCheckerSpec`/`EntryPointDetectorSpec` /
    `AnalysisContextSpec` call sites migrated to the policy enum. Suite
    total 378 (core 304 + cli 43 + coveragetool 31), all green.
  * E2E demo (log4j 2.14.1, 2026-10-09, Temurin 25.0.3, fat JAR): RTA and
    `--pointer-analysis` runs both exit 1 with 8/8 REACHABLE on the same
    ids; the SPARK graph is 316 nodes / 625 edges vs RTA's 1557 / 4923 and
    the wall time is 1.90 s vs 2.76 s (on-the-fly mode grows the graph only
    along justified calls); all 8 reported paths differ (different shortest
    routes in the subset graph — the SPARK routes are shorter) while every
    endpoint stays inside the log4j artifact: the artifact-level demo has
    no receiver-sensitive dispatch, so the verdicts are unchanged as the
    plan required.
  * Coverage gates unchanged and passing (new code lands under
    `analysis`/`engine`, already gated); SpotBugs/Checkstyle clean.
