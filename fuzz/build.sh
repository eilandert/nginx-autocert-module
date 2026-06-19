#!/usr/bin/env bash
#
# Build the autocert JSON libFuzzer target.
# Usage: fuzz/build.sh [out-binary]
#
#   - no arg      : build fuzz_json into fuzz/
#   - a file path : build fuzz_json to that path (CI / OSS-Fuzz compat)
#
# No nginx build tree required — the parser source is extracted and compiled
# against fuzz/ngx_shim.h by extract_parser.sh at build time.
#
# Requires clang with libFuzzer (clang >= 6).
# CC / CFLAGS / LIB_FUZZING_ENGINE are overridable for OSS-Fuzz and the
# valgrind-replay path (which passes CFLAGS='-g -O1' without sanitizers).

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CC="${CC:-clang}"

# OSS-Fuzz sets $LIB_FUZZING_ENGINE and its own $CFLAGS; honour them.
ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
CFLAGS="${CFLAGS:--g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined}"

ARG="${1:-}"
if [ -n "$ARG" ]; then
    OUT="$ARG"
else
    OUT="$FUZZ_DIR/fuzz_json"
fi

bash "$FUZZ_DIR/extract_parser.sh"

# shellcheck disable=SC2086
"$CC" $CFLAGS $ENGINE \
    -I"$FUZZ_DIR" \
    "$FUZZ_DIR/fuzz_json.c" \
    -o "$OUT"

echo "✓ built fuzz target: $OUT"
