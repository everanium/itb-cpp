#!/usr/bin/env bash
#
# run_bench.sh — sequential bench runner for the C++ binding.
#
# Drives the four canonical passes (Single +/-LockSeed, Triple
# +/-LockSeed) and emits one Go-bench-style line per case to stdout.
# Defaults match the cross-binding canonical: HMAC-BLAKE3 MAC,
# 1024-bit ITB key, 16 MiB CSPRNG-filled payload, ITB_BENCH_MIN_SEC=5.
#
# Usage:
#   make bench && ./run_bench.sh
#   ITB_BENCH_MIN_SEC=10 ./run_bench.sh       # tighter confidence
#   ITB_BENCH_FILTER='blake3' ./run_bench.sh  # one primitive only

set -eu
set -o pipefail

cd "$(dirname "$0")"

if [ ! -x bench/build/bench_single ] || [ ! -x bench/build/bench_triple ]; then
    echo "bench binaries missing — run \`make bench\` first" >&2
    exit 1
fi

export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

run_pass() {
    local label="$1"
    local bin="$2"
    shift 2
    echo "==== ${label} ===="
    "$bin" "$@"
}

# Pass 1: Single Ouroboros, no LockSeed.
unset ITB_LOCKSEED
run_pass "Single (no LockSeed)" ./bench/build/bench_single

# Pass 2: Single Ouroboros, LockSeed enabled.
ITB_LOCKSEED=1 run_pass "Single (LockSeed)" ./bench/build/bench_single

# Pass 3: Triple Ouroboros, no LockSeed.
unset ITB_LOCKSEED
run_pass "Triple (no LockSeed)" ./bench/build/bench_triple

# Pass 4: Triple Ouroboros, LockSeed enabled.
ITB_LOCKSEED=1 run_pass "Triple (LockSeed)" ./bench/build/bench_triple
