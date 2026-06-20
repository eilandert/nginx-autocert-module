#!/usr/bin/env bash
#
# ACME end-to-end test (M4b transport + M4c parse + M4d account bootstrap).
#
# Brings up a Pebble ACME server + a tiny dnsmasq (so the helper's ngx_resolver
# can resolve the Pebble hostname), points the helper at it with Pebble's CA in
# the trust store, starts nginx, and asserts the helper registered an ACME
# account over a *verified* TLS connection — exercising the directory fetch,
# JSON parse, newNonce header capture, JWS signing and newAccount POST, then
# the persisted 0600 account key. A negative run (no CA) proves TLS
# verification is on.
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

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
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
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_certificate $PREFIX/ca.pem;
    autocert_path $PREFIX/store;
    server {
        listen 8080;
        server_name a.example.com;
    }
}
EOF

mkdir -p "$PREFIX/store"

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start + register ACME account =="
# The helper does directory -> newNonce -> newAccount (JWS). A success line
# carrying the account kid proves the whole chain end to end: directory fetch +
# JSON parse (M4c) + Replay-Nonce header capture (M4d-1) + JWS sign (M3) + POST.
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for i in $(seq 1 40); do
    if grep -q 'autocert: ACME account registered, kid' "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    if grep -q 'autocert: ACME account registration failed' "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

echo "== helper log =="
grep autocert "$PREFIX/logs/error.log" || true

if [ -z "$ok" ]; then
    echo "::error::helper did not register an ACME account"
    exit 1
fi

echo "✓ helper registered an ACME account over verified TLS"

# kid must be a Pebble account URL (Location header was captured + carried out).
if ! grep -q 'ACME account registered, kid "https://pebble:14000/' "$PREFIX/logs/error.log"; then
    echo "::error::account kid is not a Pebble account URL"
    grep 'account registered' "$PREFIX/logs/error.log" || true
    exit 1
fi
echo "✓ account kid (Location header) captured"

# The account key was generated + persisted with 0600 perms.
if [ ! -s "$PREFIX/store/account.key" ]; then
    echo "::error::account key was not persisted"
    exit 1
fi
perms=$(stat -c '%a' "$PREFIX/store/account.key")
if [ "$perms" != "600" ]; then
    echo "::error::account key perms are $perms, expected 600"
    exit 1
fi
echo "✓ account key persisted at 0600"

# --- negative: without Pebble's CA, the self-signed cert must be REJECTED.
# Proves TLS verification is actually enabled (not verify-none).
echo "== negative: untrusted CA must fail verification =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
sleep 1

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_path $PREFIX/store;
    # no autocert_ca_certificate => system trust store, which does NOT trust
    # Pebble's self-signed CA.
    server {
        listen 8080;
        server_name a.example.com;
    }
}
EOF

# Fresh store so the account-key step succeeds and the flow reaches the TLS
# handshake (where verification must fail).
rm -rf "$PREFIX/store"; mkdir -p "$PREFIX/store"
: > "$PREFIX/logs/error.log"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

bad=
for i in $(seq 1 30); do
    # The TLS layer rejects Pebble's self-signed CA, and the account bootstrap
    # then reports failure. Either line confirms verification is on.
    if grep -Eq 'certificate verify failed|ACME account registration failed' \
            "$PREFIX/logs/error.log"; then
        bad=1; break
    fi
    if grep -q 'ACME account registered' "$PREFIX/logs/error.log"; then
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
