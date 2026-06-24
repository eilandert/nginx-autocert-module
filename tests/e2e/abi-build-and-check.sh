#!/usr/bin/env bash
#
# Self-contained ABI-drift regression. Builds the module against TWO angie trees
# that differ ONLY by a 32-byte field added to `struct ngx_ssl_s` — mimicking
# our nginx_dynamic_tls_records.patch (`ngx_ssl_dyn_rec_t dyn_rec`), which shifts
# ngx_http_ssl_srv_conf_t.certificates 208 -> 240 — then runs tests/e2e/abi-matrix.sh
# to prove: matched builds work, mismatched builds fail LOUD via the module's ABI
# guard (never SIGSEGV). Catches the exact class that crashed prod (a module
# built against the wrong tree), independent of our private deb patches.
#
# Runs in CI and locally. Needs the angie source tarball URL.
#
# Inputs (env):
#   ANGIE_URL   - angie source tarball (required, e.g. resolve job's angie_url)
#   WORKSPACE   - module checkout (default: repo root = dir-of-this-script/..)
#   WORK        - scratch dir (default: /tmp/abi-check)
#   JOBS        - make -j (default: nproc)

set -euo pipefail

ANGIE_URL="${ANGIE_URL:?set ANGIE_URL to the angie source tarball}"
WORKSPACE="${WORKSPACE:-$(cd "$(dirname "$0")/../.." && pwd)}"
WORK="${WORK:-/tmp/abi-check}"
JOBS="${JOBS:-$(nproc)}"

rm -rf "$WORK"; mkdir -p "$WORK"
curl -fsSL -o "$WORK/angie.tar.gz" "$ANGIE_URL"

# Build one flavor. $1=tree name, $2=enlarge? (yes|no)
build() {
    local name="$1"
    local enlarge="$2"
    local dir="$WORK/$name"
    mkdir -p "$dir"; tar -xzf "$WORK/angie.tar.gz" -C "$dir" --strip-components=1
    cd "$dir"
    if [ "$enlarge" = yes ]; then
        # Add 32 bytes to struct ngx_ssl_s right after `size_t buffer_size;`,
        # exactly where dynamic_tls_records inserts dyn_rec. sed (not a context
        # patch) so it survives angie version drift.
        perl -0pi -e 's/(struct ngx_ssl_s \{.*?size_t\s+buffer_size;)/$1\n    void *ngx_abi_pad_[4];/s' \
            src/event/ngx_event_openssl.h
        grep -q 'ngx_abi_pad_' src/event/ngx_event_openssl.h \
            || { echo "enlarge sed failed to match ngx_ssl_s"; exit 1; }
    fi
    AUTOCERT_TEST=1 ./configure --with-compat --with-http_ssl_module \
        --with-http_acme_module \
        --add-dynamic-module="$WORKSPACE" >"$dir/conf.log" 2>&1 \
        || { tail -30 "$dir/conf.log"; exit 1; }
    make -j"$JOBS" >"$dir/make.log" 2>&1 || { tail -30 "$dir/make.log"; exit 1; }
    test -f objs/ngx_http_autocert_module.so
    test -x objs/angie
    cd - >/dev/null
}

build vanilla  no
build enlarged yes

A_BIN="$WORK/vanilla/objs/angie"   A_BUILD="$WORK/vanilla" \
B_BIN="$WORK/enlarged/objs/angie"  B_BUILD="$WORK/enlarged" \
PREFIX="$WORK/matrix" \
    bash "$WORKSPACE/tests/e2e/abi-matrix.sh"
