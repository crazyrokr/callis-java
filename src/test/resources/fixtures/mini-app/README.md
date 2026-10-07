# mini-app fixture

A small "application under test" for the M3 call-graph tests:

- `src/app/demo/` — application classes (compiled into `classes/demo/`):
  `main()` entries, Spring/Quartz/Filter/JMS callback entries, servlet classes
  (javax/jakarta/odd/none superclass), `@Marked` non-handler annotation,
  `BadMains` signature traps, `demo/chain/` (a 16-deep interface chain plus
  a diamond, used by the callback-walk depth-cap and duplicate-seen
  branches), and the M4 positive chain `VulnCaller`/`VulnCaller2`/
  `VulnService` (main -> service -> `stublib.Stub.danger`, with the two
  callers at equal distance for the lexicographic path tie-break).
- `src/lib/` — stub framework APIs (Spring, Quartz, JMS, servlet, jakarta
  servlet) plus `stublib.Stub` (safe/danger) and `libpkg.Tool` (a library main).
- `stublib.jar` — the library classes from `src/lib/` (stublib, libpkg, jakarta).

## Rebuilding the committed binaries

The compiled `classes/` and `stublib.jar` are committed (tests run without a
toolchain on the classpath). To rebuild them after editing the sources:

```bash
cd src/test/resources/fixtures/mini-app
rm -rf build-out && mkdir -p build-out
javac -d build-out/lib $(find src/lib -name '*.java')
javac -cp build-out/lib -d build-out/app $(find src/app -name '*.java')
jar --create --file stublib.jar \
    -C build-out/lib stublib -C build-out/lib libpkg -C build-out/lib jakarta
rm -rf classes && mkdir classes && cp -r build-out/app/demo classes/
rm -rf build-out
```
