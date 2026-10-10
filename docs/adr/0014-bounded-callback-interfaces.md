# ADR 0014 — A13: Bounded callback-interface entry points

- **Status:** accepted (2026-10-05); amended: M3 verification (2026-10-06)
- **Related:** ADR 0001 (index), ADR 0007 (`main()`/annotation-driven entry points), ADR 0006 (RTA precision)

## Decision

Enterprise code reaches vulnerable code via framework callbacks (Servlet `Filter`,
Quartz `Job`, Spring `ApplicationListener`, JMS listeners) that no annotation scan
catches. App classes implementing a curated, user-extensible list
(`--callback-interfaces`) become entry points; `JavaSootClass.getInterfaces()`
verified in SootUp 3.0.1. The "all interface implementations" variant is rejected:
it would admit every business interface, inflating entry points and collapsing RTA
precision (more false positives for a security gate).

## Amendments

- **2026-10-06 (M3 verification):** callback entry points (A13) as built: the
  bounded callback list (`javax/jakarta.servlet.Filter#doFilter`,
  `org.quartz.Job#execute`,
  `org.springframework.context.ApplicationListener#onApplicationEvent`,
  `javax/jakarta.jms.MessageListener#onMessage`) resolved through the
  interface/superclass chain (depth cap 16, duplicate-seen skip). Plain
  business interfaces are **never** callback sources (precision guard,
  pinned); `--callback-interfaces` extends the list. The companion
  `main()`/annotation/`--entry-points` half of the same M3 record lives in
  ADR 0007.
