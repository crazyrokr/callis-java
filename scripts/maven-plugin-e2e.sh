#!/bin/bash
# M7e (A10): Maven plugin end-to-end — the demo (vulnerable log4j pin 2.14.1)
# must fail reachability:check with reports on disk; the fixed pin 2.25.5
# must pass. The goal is invoked directly on the demo pom, so the pom stays
# clean (no plugin wiring committed to the demo).
set -u
cd "$(dirname "$0")/.."

fail=0
step() { echo; echo "== $*"; }

step "publish core to the local Maven repository"
./gradlew -q :core:publishToMavenLocal || { echo "FAILED: :core:publishToMavenLocal"; fail=1; }

step "install reachability-maven-plugin"
./mvnw -q -f maven-plugin/pom.xml install || { echo "FAILED: plugin install"; fail=1; }

run_demo() {
    local version="$1"
    local expect="$2"
    local bom=examples/vulnerable-demo/target/bom.json
    local log=maven-plugin/target/e2e-"$version".log

    (cd examples/vulnerable-demo && ../../mvnw -B -q package -Dlog4j.version="$version") \
        || { echo "FAILED: demo build ($version)"; fail=1; return; }

    # Maven resolves relative File parameters against the project basedir,
    # so the -f invocation from the repo root needs absolute paths.
    local actual=0
    ./mvnw -B -f examples/vulnerable-demo/pom.xml \
        org.reachability:reachability-maven-plugin:0.1.0-SNAPSHOT:check \
        -Dreachability.sbomFile="$(pwd)/$bom" -Dreachability.osvDir="$(pwd)/osv-maven" > "$log" 2>&1 \
        || actual=1
    grep -E "CRITICAL|NOTICE|candidate|reachable|reachability-report" "$log" | head -15

    if [ "$expect" -eq 0 ]; then
        if [ "$actual" -eq 0 ]; then
            echo "OK: demo ($version) passes reachability:check"
        else
            echo "FAIL: demo ($version) should pass but did not (see $log)"; fail=1
        fi
    else
        if [ "$actual" -ne 0 ] \
                && [ -f examples/vulnerable-demo/target/reachability-report.json ] \
                && [ -f examples/vulnerable-demo/target/reachability-report.junit.xml ]; then
            echo "OK: demo ($version) fails with reports on disk"
        else
            echo "FAIL: demo ($version) should fail with reports (see $log)"; fail=1
        fi
    fi
}

run_demo 2.14.1 1
run_demo 2.25.5 0

exit "$fail"
