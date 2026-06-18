#!/usr/bin/env bash
#
# M7 per-SNI certificate serving test (no network / no docker).
#
# A `listen ssl; autocert on;` server with NO ssl_certificate must:
#   1. start (autocert seeds a bootstrap SSL_CTX so the listener comes up),
#   2. serve a self-signed bootstrap cert (CN=localhost) when no real cert is
#      yet on disk for the requested SNI,
#   3. serve the real <store>/<sni>/fullchain.pem once it exists, picked by SNI,
#   4. hot-reload a renewed cert (changed mtime) with NO config reload.
#
# Real issuance against Pebble is covered by order-authz.sh; this test exercises
# the serve path in isolation by dropping certs into the store directly.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

PROC_SO="$NGX_BUILD_DIR/objs/ngx_autocert_process_module.so"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$PROC_SO" ] || { echo "missing $PROC_SO"; exit 1; }
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-tls-serve}"
PORT="${AC_TEST_PORT:-8443}"
DOMAIN="a.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store/$DOMAIN"

# A real (self-signed) leaf for the domain, in the SECURE store layout.
gen_cert() {
    # $1 = subject CN / SAN domain ; writes fullchain.pem + privkey.pem
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$PREFIX/store/$1/privkey.pem" \
        -out    "$PREFIX/store/$1/fullchain.pem" \
        -days 2 -subj "/CN=$1" -addext "subjectAltName=DNS:$1" >/dev/null 2>&1
    chmod 600 "$PREFIX/store/$1/privkey.pem"
}

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert_path $PREFIX/store;
    server {
        listen $PORT ssl;
        server_name $DOMAIN;
        autocert on;
    }
}
EOF

echo "== config test (listen ssl + autocert on, no ssl_certificate) =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted with no ssl_certificate"

# --- negative config cases (must be rejected at -t) ---
expect_reject() {
    # $1 = conf file, $2 = grep pattern that must appear in the emerg.
    # nginx -t exits non-zero on rejection; capture output so pipefail/-e on the
    # nginx exit code doesn't mask a successful grep match.
    local out
    out="$("$SERVER_BIN" -t -p "$PREFIX" -c "$1" 2>&1 || true)"
    if printf '%s\n' "$out" | grep -q "$2"; then
        echo "✓ rejected: $2"
    else
        echo "::error::config not rejected as expected ($2)"
        printf '%s\n' "$out" | sed 's/^/    /'
        exit 1
    fi
}

cat > "$PREFIX/conf/neg-var-cert.conf" <<EOF
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/neg.log notice;
events {}
http {
    autocert_path $PREFIX/store;
    map \$ssl_server_name \$cf { default /x.pem; }
    server {
        listen $PORT ssl; server_name $DOMAIN; autocert on;
        ssl_certificate \$cf; ssl_certificate_key \$cf;
    }
}
EOF
echo "== reject: variable ssl_certificate + autocert on =="
expect_reject "$PREFIX/conf/neg-var-cert.conf" 'variable .*ssl_certificate'

# helper: subject CN served for a given SNI ("" = no SNI)
served_subject() {
    local sni_arg=()
    [ -n "$1" ] && sni_arg=(-servername "$1")
    echo | openssl s_client -connect "127.0.0.1:$PORT" "${sni_arg[@]}" 2>/dev/null \
        | openssl x509 -noout -subject 2>/dev/null
}
served_serial() {
    echo | openssl s_client -connect "127.0.0.1:$PORT" -servername "$1" 2>/dev/null \
        | openssl x509 -noout -serial 2>/dev/null
}

echo "== start (no cert on disk yet) =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do
    echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | grep -q CONNECTED && break
    sleep 0.2
done

echo "== bootstrap cert before issuance (expect CN=localhost) =="
boot=$(served_subject "$DOMAIN")
case "$boot" in
    *CN*=*localhost) echo "✓ bootstrap cert served pre-issuance ($boot)";;
    *) echo "::error::expected bootstrap CN=localhost, got '$boot'"; exit 1;;
esac

echo "== drop real cert into store, serve it by SNI (expect CN=$DOMAIN) =="
gen_cert "$DOMAIN"
# defeat the 1s stat throttle
sleep 1.2
sub=$(served_subject "$DOMAIN")
case "$sub" in
    *CN*=*"$DOMAIN") echo "✓ real store cert served for SNI $DOMAIN ($sub)";;
    *) echo "::error::expected CN=$DOMAIN, got '$sub'"; exit 1;;
esac

echo "== no-SNI handshake still serves bootstrap (no store lookup) =="
nosni=$(served_subject "")
case "$nosni" in
    *CN*=*localhost) echo "✓ no-SNI keeps bootstrap cert ($nosni)";;
    *) echo "::error::no-SNI expected CN=localhost, got '$nosni'"; exit 1;;
esac

echo "== hot-reload on mtime change (no config reload) =="
before=$(served_serial "$DOMAIN")
sleep 1.2
gen_cert "$DOMAIN"          # new serial, same name
sleep 1.2
after=$(served_serial "$DOMAIN")
if ! { [ -n "$before" ] && [ -n "$after" ]; }; then echo "::error::missing serial"; exit 1; fi
[ "$before" != "$after" ] || {
    echo "::error::serial unchanged after renew ($before) — no hot-reload"; exit 1; }
echo "✓ renewed cert picked up without reload ($before -> $after)"

echo "✓ M7 per-SNI certificate serving verified"
