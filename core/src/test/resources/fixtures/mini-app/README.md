# mini-app fixture

A small "application under test" for the M3 call-graph tests:

- `src/app/demo/` — application classes (compiled into `classes/demo/`):
  `main()` entries, Spring/Quartz/Filter/JMS callback entries, servlet classes
  (javax/jakarta/odd/none superclass), `@Marked` non-handler annotation,
  `BadMains` signature traps, `demo/chain/` (a 16-deep interface chain plus
  a diamond, used by the callback-walk depth-cap and duplicate-seen
  branches), the M4 positive chain `VulnCaller`/`VulnCaller2`/`VulnService`
  (main -> service -> `stublib.Stub.danger`, with the two callers at equal
  distance for the lexicographic path tie-break), and the M7b pointer-analysis
  fixtures: `PIface` (interface), `SafeImpl`/`DangerImpl` (safe/dangerous
  implementations), `PointerDemo` (constructs only `SafeImpl`, calls
  `ref.op()`) and `PointerDemo2` (instantiates `DangerImpl` by assignment but
  never dispatches to it — the class SootUp's RTA keeps as an instantiation
  false positive while SPARK prunes).
- `src/lib/` — stub framework APIs (Spring, Quartz, JMS, servlet, jakarta
  servlet) plus `stublib.Stub` (safe/danger) and `libpkg.Tool` (a library main).
- `stublib.jar` — the library classes from `src/lib/` (stublib, libpkg, jakarta).

## Generated binaries (M7a)

Nothing binary is committed here: the `core` build generates them from the
sources in `src/` before any test runs (the generated paths are gitignored):
`compileFixtureLib` compiles `src/lib`, `stublibJar` jars the stublib/libpkg/
jakarta packages into `stublib.jar`, and `compileFixtureApp` compiles
`src/app` (against that jar) into `classes/`. Editing a source file is all
that is needed to change the fixture — `./gradlew :core:test` regenerates.

The bytecode probes (`fixtures/bytecode/`) work the same way:
`generateFixtureBytecode` compiles the committed `v69/Release25Probe.java`
and reproduces `v70/TooNewProbe.class` byte-exactly from a 61-byte
hand-crafted probe — a v70 header over a deliberately broken constant pool.
A fully valid v70 class parses fine under SootUp 3.0.1's ASM, so the
zero-classes contract (A12) needs the unparseable body, while the guard's
header scan still reads major 70. (No javac 25 can emit v70 at all.)
