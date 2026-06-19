#!/usr/bin/env bash
#
# Slice the JSON parser bodies out of the shipped
# ../src/ngx_autocert_json.c into generated_json.inc for standalone
# compilation against ngx_shim.h — no real nginx headers required.
#
# What we extract:
#   - The NGX_AUTOCERT_JSON_MAX_DEPTH #define
#   - The internal context struct (ngx_autocert_json_ctx_t)
#   - All static helper functions (skip_ws, alloc, utf8, hex4,
#     string_raw, number, literal, value, object, array)
#   - The six public functions (parse, object_get, object_str,
#     array_item, array_count, number_int)
#
# The .h includes (#include "ngx_autocert_json.h") are stripped and
# replaced with a sentinel comment so the harness can inject the shim
# header + a stripped copy of the type declarations instead.
#
# This keeps the fuzz target locked to production code: there is no
# hand-copied parser.  If a signature or body changes upstream, the
# next fuzz build picks it up automatically.  If a required symbol can
# no longer be found, we fail loudly rather than silently fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../src/ngx_autocert_json.c"
HDR="$FUZZ_DIR/../src/ngx_autocert_json.h"
OUT="$FUZZ_DIR/generated_json.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi
if [ ! -f "$HDR" ]; then
    echo "✗ cannot find $HDR" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Part 1: emit a stripped copy of ngx_autocert_json.h — types only, with
# the real nginx header includes replaced by nothing (our shim already
# provides all types the parser needs).
# ---------------------------------------------------------------------------
{
    echo "/* --- types from ngx_autocert_json.h (nginx includes stripped) --- */"
    awk '
        /^#ifndef _NGX_AUTOCERT_JSON_H_INCLUDED_/ { in_guard=1; print; next }
        in_guard && /^#include/ { next }
        in_guard { print }
    ' "$HDR"
    echo ""
} > "$OUT"

# ---------------------------------------------------------------------------
# Part 2: emit the .c body with its #include "ngx_autocert_json.h" stripped
# (we already have the types above) and with the two macros the parser uses
# that the shim doesn't define: uint32_t (already in stdint via shim) and
# NGX_AUTOCERT_JSON_MAX_DEPTH (defined in the .c itself — keep it).
# ---------------------------------------------------------------------------
{
    echo "/* --- parser bodies from ngx_autocert_json.c (nginx includes stripped) --- */"
    awk '
        /^#include/ { next }
        { print }
    ' "$SRC"
} >> "$OUT"

# ---------------------------------------------------------------------------
# Sanity: all six public entry points must be present in the output.
# ---------------------------------------------------------------------------
for fn in \
    'ngx_autocert_json_parse(' \
    'ngx_autocert_json_object_get(' \
    'ngx_autocert_json_object_str(' \
    'ngx_autocert_json_array_item(' \
    'ngx_autocert_json_array_count(' \
    'ngx_autocert_json_number_int('
do
    if ! grep -qF "$fn" "$OUT"; then
        echo "✗ failed to find $fn in generated output" >&2
        echo "  (source layout changed? update extract_parser.sh)" >&2
        rm -f "$OUT"
        exit 1
    fi
done

LINES=$(wc -l < "$OUT")
echo "✓ extracted ngx_autocert_json types + parser bodies — $LINES lines -> $OUT"
