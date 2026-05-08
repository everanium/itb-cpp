#!/usr/bin/env bash
#
# run_tests.sh — sequential test runner for the C++ binding.
#
# Discovers every binary under tests/build/ produced by `make tests`
# and runs them one at a time, mirroring the C binding's runner.
# Catch2 v3's default reporter prints PASS / FAIL per test case; this
# wrapper aggregates the per-binary exit codes.
#
# Usage:
#   make tests && ./run_tests.sh
#   ITB_TEST_FILTER='blake3' ./run_tests.sh   # passes filter to Catch2

set -eu
set -o pipefail

cd "$(dirname "$0")"

if [ ! -d tests/build ]; then
    echo "tests/build/ missing — run \`make tests\` first" >&2
    exit 1
fi

shopt -s nullglob
BINS=(tests/build/test_*)
if [ ${#BINS[@]} -eq 0 ]; then
    echo "no test binaries in tests/build/ — Phase 7.5 not yet wired" >&2
    exit 1
fi

PASS=0
FAIL=0
FILTER_ARGS=()
if [ -n "${ITB_TEST_FILTER:-}" ]; then
    FILTER_ARGS=("$ITB_TEST_FILTER")
fi

for bin in "${BINS[@]}"; do
    name=$(basename "$bin")
    if "$bin" "${FILTER_ARGS[@]}"; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $name" >&2
    fi
done

echo "----"
echo "result: $PASS passed, $FAIL failed (of $((PASS + FAIL)))"
[ $FAIL -eq 0 ]
