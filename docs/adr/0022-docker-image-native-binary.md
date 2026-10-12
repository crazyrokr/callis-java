# ADR 0022 — Docker image of the native binary, published to GitHub Packages

- **Status:** accepted (2026-10-12)
- **Related:** ADR 0003 (Fat-JAR / native binary), ADR 0001 (index)

## Decision

The M7d native binary ships as a container image, `ghcr.io/<owner>/
reachability-analyzer`, so consumers can `docker pull` instead of building
under GraalVM.

- **Base: `FROM gcr.io/distroless/base`.** The current
  `:cli:nativeCompile` output is statically linked except for the C
  runtime (native-image's default static-partial): `ldd` shows only glibc
  (`libc`/`libm`/`ld-linux`) and `libz`. `FROM scratch` cannot run such a
  binary (no dynamic loader), and distroless `base` is the smallest image
  that provides those libraries — no shell, no package manager, nothing
  else to patch; ~24 MB compressed (89 MB unpacked). Consequence,
  recorded: no shell inside —
  `--help`/`-V` work (picocli), an interactive `sh` does not (documented
  in the README). (The 21.5 MB / "staticly linked" figures in ADR 0003
  no longer hold; see the 0003 amendment.)
- **Image shape:** `WORKDIR /work`, `ENTRYPOINT` = the binary,
  `CMD ["--help"]` so a bare `docker run` prints usage instead of failing
  on the missing required options; the first user-supplied argument
  replaces the CMD. `--output=<base>` and relative input paths resolve
  against `/work`, i.e. the first mount.
- **Build context: the binary's directory only**
  (`cli/build/native/nativeCompile`, in CI the `nativeCompile/` content
  of the `reachability-analyzer-native` artifact) — only the 21.5 MB
  binary reaches the builder. `docker/Dockerfile` is outside the context
  (buildx `-f`).
- **CI (build-analyzer.yml, new `docker` job):** `needs: native`,
  `if: github.event_name == 'push'` (PR tokens cannot push to GitHub
  Packages), job-level `permissions: contents: read, packages: write`
  (least privilege — the other jobs stay on the workflow-level
  `contents: read`). Login via `GITHUB_TOKEN`; tags `latest` and
  `<commit sha>`, OCI labels `org.opencontainers.image.source`/`revision`.
- **Single-arch `linux/amd64`:** the binary is built on the amd64 runner;
  multi-arch would need a per-arch `nativeCompile`, deferred.

## Verification (2026-10-12)

Built locally under GraalVM 25.0.3, `docker build` from
`cli/build/native/nativeCompile`, `docker run --version` and `--help`
sanity, then the full vulnerable demo **inside the container** (project
mounted at `/work`, the 39 MB OSV snapshot at `/osv:ro`, the local
Maven repository at its recorded absolute path): exit **1** with 8/8
REACHABLE matching `expected-reachable.txt`, all three report formats
written into the mounted workdir. The classpath pitfall was found by
that test — without the repository mount the log4j jars are unreadable
from inside, the verdict degrades to `NO_CLASS_INFO`, and the run exits
**0** (silently green); the README documents the mount.
