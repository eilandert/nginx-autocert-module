#!/usr/bin/env bash
#
# Build autocert libFuzzer targets.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${1:-$FUZZ_DIR}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:?set NGX_BUILD_DIR to a configured nginx build tree}"
CC="${CC:-clang}"

ENGINE="${LIB_FUZZING_ENGINE:--fsanitize=fuzzer}"
CFLAGS="${CFLAGS:--g -O1 -fsanitize=address,undefined -fno-sanitize-recover=undefined}"

mkdir -p "$OUT_DIR"

INC=(
    -I"$NGX_BUILD_DIR/src/core"
    -I"$NGX_BUILD_DIR/src/event"
    -I"$NGX_BUILD_DIR/src/os/unix"
    -I"$NGX_BUILD_DIR/objs"
)
OBJS=(
    "$NGX_BUILD_DIR/objs/src/core/ngx_palloc.o"
    "$NGX_BUILD_DIR/objs/src/core/ngx_string.o"
    "$NGX_BUILD_DIR/objs/src/os/unix/ngx_time.o"
    "$NGX_BUILD_DIR/objs/src/core/ngx_times.o"
    "$NGX_BUILD_DIR/objs/src/os/unix/ngx_alloc.o"
)

for obj in "${OBJS[@]}"; do
    test -f "$obj"
done

# CFLAGS and ENGINE are flag lists supplied by libFuzzer/OSS-Fuzz tooling.
# shellcheck disable=SC2086
"$CC" $CFLAGS $ENGINE "${INC[@]}" \
    "$FUZZ_DIR/fuzz_json.c" \
    "$FUZZ_DIR/../src/ngx_autocert_json.c" \
    "${OBJS[@]}" \
    -o "$OUT_DIR/fuzz_json"

echo "built fuzz target: $OUT_DIR/fuzz_json"
