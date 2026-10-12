# reachability-analyzer — the M7d GraalVM native binary (ADR 0003).
#
# The binary is statically linked except for the C runtime (native-image
# static-partial): ldd shows only glibc (libc/libm/ld-linux) and libz.
# FROM scratch therefore cannot run it (no dynamic loader), and
# gcr.io/distroless/base is the smallest image that provides those
# libraries — no shell, no package manager, nothing else to patch.
# Total image: ~24 MB compressed (89 MB unpacked).
#
# Build context: the binary's directory only, so nothing but the 35.8 MB
# binary reaches the builder.
#   CI:     the `reachability-analyzer-native` artifact's `nativeCompile/`
#          (upload path `cli/build/native/` in the `native` job)
#   local:  cli/build/native/nativeCompile
#           (after JAVA_HOME=<GraalVM 25> ./gradlew :cli:nativeCompile)
FROM gcr.io/distroless/base:latest

COPY cli /usr/local/bin/reachability-analyzer

# Reports from --output=<base> and relative input paths resolve against
# the workdir; consumers mount their project here.
WORKDIR /work

ENTRYPOINT ["/usr/local/bin/reachability-analyzer"]
# A bare `docker run <image>` prints usage instead of failing on the
# missing required options; the first user-supplied argument replaces it.
CMD ["--help"]
