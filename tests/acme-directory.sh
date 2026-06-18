#!/usr/bin/env bash
#
# M4b end-to-end test: the helper fetches the CA directory over TLS.
#
# Brings up a Pebble ACME server + a tiny dnsmasq (so the helper's ngx_resolver
# can resolve the Pebble hostname), points the helper at it with Pebble's CA in
# the trust store, starts nginx, and asserts the helper logged a successful
# directory fetch over a *verified* TLS connection.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)
#
# Exercises: URL parse, ngx_resolver, ngx_event_connect_peer, ngx_ssl handshake
# + peer cert verification against a custom CA, HTTP/1.1 GET, response parse.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
# SERVER_BIN is <build>/objs/nginx; the .so files sit beside it in objs/, so
# the build dir is two levels up from the binary.
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

PROC_SO="$NGX_BUILD_DIR/objs/ngx_autocert_process_module.so"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$PROC_SO" ] || { echo "missing $PROC_SO"; exit 1; }
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-acme-dir}"
PEBBLE_NAME="ac-pebble-$$"
DNS_NAME="ac-dns-$$"
DNS_PORT=15353

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf"

echo "== starting Pebble =="
docker run -d --name "$PEBBLE_NAME" -p 14000:14000 -p 15000:15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    ghcr.io/letsencrypt/pebble:latest >/dev/null

echo "== starting dnsmasq (resolves 'pebble' -> 127.0.0.1) =="
docker run -d --name "$DNS_NAME" -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/pebble/127.0.0.1 >/dev/null

# Wait for Pebble's ACME endpoint to answer.
for i in $(seq 1 30); do
    if curl -ksf https://127.0.0.1:14000/dir >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "Pebble did not come up"; docker logs "$PEBBLE_NAME"; exit 1; }
done

# Pebble's ACME (:14000) cert is signed by this baked-in mini CA.
docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PREFIX/ca.pem"

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_certificate $PREFIX/ca.pem;
    server {
        listen 8080;
        server_name a.example.com;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start + fetch directory =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for i in $(seq 1 30); do
    if grep -q 'autocert: ACME directory OK, status 200' "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    if grep -q 'autocert: ACME directory fetch failed' "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

echo "== helper log =="
grep autocert "$PREFIX/logs/error.log" || true

if [ -z "$ok" ]; then
    echo "::error::helper did not fetch the ACME directory over TLS"
    exit 1
fi

echo "✓ helper fetched the ACME directory over verified TLS"

# The success line echoes a response header captured by the client
# (ngx_autocert_acme_header). Pebble serves the directory as application/json,
# so a captured, non-empty Content-Type proves header capture works e2e.
if ! grep -q 'ACME directory OK.*content-type "application/json' "$PREFIX/logs/error.log"; then
    echo "::error::Content-Type response header was not captured"
    grep 'ACME directory OK' "$PREFIX/logs/error.log" || true
    exit 1
fi
echo "✓ response header (Content-Type) captured by the client"

# --- negative: without Pebble's CA, the self-signed cert must be REJECTED.
# Proves TLS verification is actually enabled (not verify-none).
echo "== negative: untrusted CA must fail verification =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
sleep 1

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    # no autocert_ca_certificate => system trust store, which does NOT trust
    # Pebble's self-signed CA.
    server {
        listen 8080;
        server_name a.example.com;
    }
}
EOF

> "$PREFIX/logs/error.log"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

bad=
for i in $(seq 1 30); do
    if grep -q 'autocert: ACME directory fetch failed' "$PREFIX/logs/error.log"; then
        bad=1; break
    fi
    if grep -q 'autocert: ACME directory OK' "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

grep autocert "$PREFIX/logs/error.log" || true

if [ -z "$bad" ]; then
    echo "::error::untrusted ACME CA was NOT rejected (TLS verification is off)"
    exit 1
fi

echo "✓ untrusted ACME CA correctly rejected"
