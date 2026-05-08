#!/usr/bin/env bash
#
# build.sh — one-step build for the C++ binding's prerequisites.
#
# The C++ binding is header-only, so there is nothing to compile for
# the library itself. This script chains the prerequisite builds:
#
#   1. libitb.so (Go-built c-shared from the repo root).
#   2. libitb_c.a (the C binding's static archive).
#
# Once both prerequisites exist, consumer applications and the C++
# binding's own test / bench binaries can be compiled against the
# headers in include/.
#
# Prerequisites: Go, a C17 compiler (for the C binding), a C++17
# compiler, GNU make, libcheck (for C-binding tests), Catch2 v3 (for
# C++-binding tests). See README.md for the Arch / Debian package
# names.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

NOITBASM=""
case "${1:-}" in
    --noitbasm) NOITBASM="--noitbasm"; shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

# Step 1 + 2 — delegate to the C binding's build.sh which chains
# libitb.so + libitb_c.a in one step. The chained call performs its
# own `make clean` against the C binding's tree before rebuilding.
cd "$SCRIPT_DIR"
echo "==> cleaning previous C++ build artefacts (make clean)"
make clean 2>/dev/null || true
mkdir -p tests/build bench/build
echo "==> chaining ../c/build.sh ${NOITBASM}"
(cd ../c && ./build.sh ${NOITBASM:+$NOITBASM})

# Step 3 — verify header is in sync (cheap CI gate; protects against a
# stale include/itb.h after a libitb ABI change).
echo "==> ./check_header.sh"
./check_header.sh

echo "==> ready: make tests / make bench"
