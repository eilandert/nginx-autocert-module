#!/usr/bin/env bash
#
# ABI cross-matrix. A dynamic module bakes in the compile-time offsets of every
# core/ssl struct field it reads. Our packages carry nginx_dynamic_tls_records,
# which adds ngx_ssl_dyn_rec_t to ngx_ssl_s (+32B) and shifts
# ngx_http_ssl_srv_conf_t.certificates 208 -> 240. A module built against the
# OTHER layout reads certificates from the wrong bytes. nginx's own ABI guard
# (NGX_MODULE_SIGNATURE) would refuse such a module, but our packages pin the
# signature, so the mismatched .so loads and SIGSEGVs in serve_init.
#
# This proves, for two pre-built flavors A and B that differ ONLY by the
# struct-enlarging patch:
#   matched A.so -> A bin   : -t OK   (module works for that layout)
#   matched B.so -> B bin   : -t OK
#   cross  A.so -> B bin    : refused with the [emerg] ABI guard, NOT a signal
#   cross  B.so -> A bin    : refused with the [emerg] ABI guard, NOT a signal
#
# i.e. "works with and without the patch" when matched, and fails LOUD (never a
# crash) when mismatched.
#
# Inputs (env):
#   A_BIN  A_BUILD   - flavor A binary + build dir (objs/ngx_http_autocert_module.so)
#   B_BIN  B_BUILD   - flavor B binary + build dir
# A_BUILD/B_BUILD default to dir-of-bin/..

set -euo pipefail

A_BIN="${A_BIN:?set A_BIN}"; B_BIN="${B_BIN:?set B_BIN}"
A_BUILD="${A_BUILD:-$(cd "$(dirname "$A_BIN")/.." && pwd)}"
B_BUILD="${B_BUILD:-$(cd "$(dirname "$B_BIN")/.." && pwd)}"

PREFIX="${PREFIX:-/tmp/ac-abimatrix}"
LDPATH="${LDPATH:-}"     # optional LD_LIBRARY_PATH for a relocated binary

fails=0

# Build a minimal coexistence-ish config that has a real ssl server (so
# serve_init reaches the drift-prone field reads).
make_conf() {
    local so="$1" dir="$2"
    mkdir -p "$dir/logs" "$dir/store"
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$dir/k" -out "$dir/c" -days 1 -nodes -subj /CN=d >/dev/null 2>&1
    cat > "$dir/nginx.conf" <<EOF
load_module $so;
error_log $dir/logs/err.log;
pid $dir/p.pid;
events {}
http {
    access_log off;
    client_body_temp_path $dir/body;
    proxy_temp_path $dir/proxy;
    fastcgi_temp_path $dir/fcgi;
    uwsgi_temp_path $dir/uwsgi;
    scgi_temp_path $dir/scgi;
    autocert_store_path $dir/store;
    autocert_contact a@b.com;
    server {
        listen 127.0.0.1:8444 ssl;
        server_name auto.example.com;
        autocert on;
        ssl_certificate $dir/c;
        ssl_certificate_key $dir/k;
    }
}
EOF
}

# run <label> <bin> <so> <expect: ok|guard>
run_case() {
    local label="$1" bin="$2" so="$3" expect="$4"
    local dir="$PREFIX/$label"; rm -rf "$dir"; make_conf "$so" "$dir"
    local out rc=0
    if [ -n "$LDPATH" ]; then
        out=$(LD_LIBRARY_PATH="$LDPATH" "$bin" -t -p "$dir" -c "$dir/nginx.conf" 2>&1) || rc=$?
    else
        out=$("$bin" -t -p "$dir" -c "$dir/nginx.conf" 2>&1) || rc=$?
    fi

    if [ "$rc" -ge 128 ]; then
        echo "::error::[$label] CRASH on signal $((rc-128)) — ABI guard failed to catch the mismatch"
        fails=$((fails+1)); return
    fi
    case "$expect" in
        ok)
            if [ "$rc" -ne 0 ]; then
                echo "::error::[$label] matched build should -t OK but exit=$rc"
                printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails+1))
            else echo "✓ [$label] matched -t OK"; fi ;;
        guard)
            if printf '%s' "$out" | grep -q 'autocert: ngx_http_ssl_srv_conf_t ABI mismatch'; then
                echo "✓ [$label] mismatch refused by ABI guard (exit $rc, no crash)"
            else
                echo "::error::[$label] mismatch NOT caught by guard (exit $rc)"
                printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails+1))
            fi ;;
    esac
}

A_SO="$A_BUILD/objs/ngx_http_autocert_module.so"
B_SO="$B_BUILD/objs/ngx_http_autocert_module.so"
for f in "$A_BIN" "$B_BIN" "$A_SO" "$B_SO"; do [ -e "$f" ] || { echo "missing $f"; exit 1; }; done

run_case A-matched   "$A_BIN" "$A_SO" ok
run_case B-matched   "$B_BIN" "$B_SO" ok
run_case A-into-B    "$B_BIN" "$A_SO" guard
run_case B-into-A    "$A_BIN" "$B_SO" guard

if [ "$fails" -eq 0 ]; then
    echo "ABI matrix: ALL PASS"
else
    echo "ABI matrix: $fails FAIL"; exit 1
fi
