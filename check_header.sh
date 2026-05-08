#!/usr/bin/env bash
#
# check_header.sh — CI gate that fails when include/itb.h has drifted
# from bindings/c/include/itb.h.
#
# Strips the AUTO-DERIVED stamp from include/itb.h, then byte-compares
# the remainder against the C binding's source header. Any non-zero
# exit indicates the C++ binding's header copy is stale; run
# sync_header.sh to refresh.
#
# Usage:
#   ./check_header.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
SOURCE="../c/include/itb.h"
TARGET="include/itb.h"

if [ ! -f "$TARGET" ]; then
    echo "check_header.sh: ${TARGET} missing — run sync_header.sh" >&2
    exit 1
fi

# The stamp is a fixed comment block followed by one blank line, ending
# at the first occurrence of '/*' that is NOT preceded by another '*/'.
# To stay simple and portable, drop everything up to and including the
# first blank line after the stamp's closing '*/'. The exact rule:
# strip lines until the first one that begins with '/*' AND is followed
# by ' * itb.h' (the C header's own opening comment), then resume.
TARGET_STRIPPED=$(awk '
    BEGIN { skip = 1 }
    skip && /^\/\*/ && getline next_line {
        # Re-emit the next_line by buffering and checking content.
        if (next_line ~ /^ \* itb\.h/) {
            skip = 0
            print
            print next_line
            next
        }
        next
    }
    !skip { print }
' "$TARGET")

if ! diff -u <(echo "$TARGET_STRIPPED") "$SOURCE" >/dev/null 2>&1; then
    echo "check_header.sh: include/itb.h has drifted from ${SOURCE}" >&2
    echo "                 run ./sync_header.sh to refresh" >&2
    diff -u <(echo "$TARGET_STRIPPED") "$SOURCE" >&2 || true
    exit 1
fi

echo "check_header.sh: include/itb.h is in sync with ${SOURCE}"
