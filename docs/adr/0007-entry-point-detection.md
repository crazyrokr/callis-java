# ADR 0007 — A6: Entry points: `main()` + annotation-driven + `--entry-points` override

- **Status:** accepted (2026-10-05); amended: M3 verification (2026-10-06)
- **Related:** ADR 0001 (index), ADR 0014 (bounded callback interfaces), ADR 0006 (call-graph policies)

## Decision

`main(String[])` in **app classes only** (never library mains), plus bytecode-level
annotation scan for the frameworks in the spec: Spring controllers/handlers,
`@Scheduled`, JMS/Kafka/Rabbit listeners, `@WebServlet`/`doGet`/`doPost`, Quartz
`execute()`. Annotations are read from bytecode — no framework classpath needed.
An explicit `--entry-points class#method` list wins over auto-detection.

## Amendments

- **2026-10-06 (M3 verification):** entry-point detection (A6) as built:
  `main(String[])` of **app classes only** (library mains in jars are never
  entries); framework handler annotations read from bytecode
  (`org.springframework.web.bind.annotation.*`, `@Scheduled`, `@KafkaListener`,
  `@RabbitListener`); `doGet`/`doPost` of `@WebServlet` (javax/jakarta)
  classes or `HttpServlet`/`jakarta HttpServlet` subclasses;
  `--entry-points class#method` overrides auto-detection (malformed /
  unknown entries are warned, not fatal). The bounded callback-interface
  list (A13) of the same M3 record is verified in ADR 0014.

- **2026-10-06 (M3 verification):** SootUp `ArrayType.getBaseType()` unwraps
  **multi-dimensional** arrays to the innermost element (`String[][]` →
  `String`), so the `main(String[])` check needed an explicit
  `getDimension() == 1` — without it `main(String[][])` is accepted as a JVM
  entry point (false positive; the `BadMains` fixture pins all five trap
  overloads as non-entries).

- **2026-10-06 (M3 verification):** the fixture `fixtures/mini-app` grows to
  46 app classes (servlet superclass matrix, `@Marked` non-handler
  annotation, `BadMains` traps, a 16-deep interface chain + diamond for the
  walk depth cap) with `StubSootClass`/`StubSootMethod`/`FakeView` test
  doubles for the `SootClass`/`SootMethod` annotation fallbacks (SootUp 3.0.1
  exposes those as interfaces, so non-Java model objects are testable). The
  `examples/vulnerable-demo` < 60 s build-time acceptance is measured in M6,
  when the demo is created. (The `analysis` package branch numbers of the
  same M3 record live in ADR 0018.)
