#!/usr/bin/env bash
#
# sync_header.sh — refresh include/itb.h from the C binding's public
# header.
#
# The C++ binding's RAII wrappers in include/itb/*.hpp call the C
# binding's `itb_*` API exclusively; the public C header is consumed
# verbatim. To avoid maintenance drift between the two sibling bindings,
# include/itb.h is a derived COPY of bindings/c/include/itb.h with a
# header stamp identifying its provenance.
#
# Run this script after every libitb ABI change (or any edit to the C
# binding's public header). The CI gate `check_header.sh` fails when the
# two files have drifted.
#
# Usage:
#   ./sync_header.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
SOURCE="../c/include/itb.h"
TARGET="include/itb.h"

if [ ! -f "$SOURCE" ]; then
    echo "sync_header.sh: source header missing at $SOURCE" >&2
    exit 1
fi

STAMP="\
/* AUTO-DERIVED FROM bindings/c/include/itb.h — DO NOT EDIT.
 *
 * The C++ binding's RAII wrappers under include/itb/ consume the
 * libitb C ABI through this header verbatim. To keep the two sibling
 * bindings in lock-step, run bindings/cpp/sync_header.sh after every
 * libitb ABI change; the CI gate bindings/cpp/check_header.sh fails on
 * drift.
 */
"

mkdir -p include
{
    printf '%s\n' "$STAMP"
    cat "$SOURCE"
} > "$TARGET"

echo "sync_header.sh: ${TARGET} refreshed from ${SOURCE}"
