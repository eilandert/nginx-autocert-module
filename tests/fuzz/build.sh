#!/usr/bin/env bash
#
# Build the autocert libFuzzer targets.
# Usage: fuzz/build.sh [out-dir]
#
#   - no arg   : build fuzz_json + fuzz_http into fuzz/
#   - a dir    : build fuzz_json + fuzz_http into that directory
#                (CI / OSS-Fuzz compat — $OUT/$OUT_DIR convention)
#
# Two targets:
#   fuzz_json  — ngx_autocert_json_parse + accessors   (generated_json.inc)
#   fuzz_http  — ngx_autocert_acme_parse_response/dechunk (generated_http.inc)
#
# No nginx build tree required — each parser's source is sliced from the shipped
# .c by its extract_*.sh and compiled against the matching fuzz/ngx_*shim.h, so
# the fuzzers always exercise production code with no copy drift.
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

OUT_DIR="${1:-$FUZZ_DIR}"

# Regenerate both slices from the shipped source.
bash "$FUZZ_DIR/extract_parser.sh"
bash "$FUZZ_DIR/extract_http.sh"

build_one() {
    target="$1"
    # shellcheck disable=SC2086
    "$CC" $CFLAGS $ENGINE \
        -I"$FUZZ_DIR" \
        "$FUZZ_DIR/${target}.c" \
        -o "$OUT_DIR/${target}"
    echo "✓ built fuzz target: $OUT_DIR/${target}"
}

build_one fuzz_json
build_one fuzz_http
