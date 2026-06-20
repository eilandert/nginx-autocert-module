#!/usr/bin/env bash
#
# M10b tls-alpn-01 ALPN serve-path test (no network / no docker).
#
# A `listen ssl; autocert on; autocert_challenge tls-alpn-01;` server must, when
# a client negotiates ALPN "acme-tls/1" + SNI=<domain> (an ACME CA's RFC 8737
# validation handshake), serve the challenge certificate the helper placed in
# the shared store — a self-signed cert carrying SAN=<domain> and the CRITICAL
# id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31) — instead of the
# real/bootstrap cert. A normal handshake (no acme-tls/1) must still get the
# ordinary cert and negotiate http/1.1.
#
# The challenge cert is seeded directly (autocert_test_alpn) so the serve path
# is exercised without a real ACME order; full issuance with tls-alpn-01 over
# Pebble is M10c. The acmeIdentifier digest itself is unit-tested in M10a
# (test_crypto.c); here we assert the SERVE PATH selects and presents that cert.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-tls-alpn}"
PORT="${AC_TEST_PORT:-8543}"
DOMAIN="alpn.example.com"
KEYAUTH="test-token.0123456789abcdef0123456789abcdef0123456789ab"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert_path $PREFIX/store;
    autocert_challenge tls-alpn-01;
    autocert_test_alpn $DOMAIN $KEYAUTH;
    server {
        listen $PORT ssl;
        server_name $DOMAIN;
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# Wait for the helper to seed the challenge cert into the shared store.
for _ in $(seq 1 50); do
    grep -q "seeded test tls-alpn-01 cert" "$PREFIX/logs/error.log" && break
    sleep 0.1
done
grep -q "seeded test tls-alpn-01 cert" "$PREFIX/logs/error.log" \
    || { echo "::error::helper did not seed the challenge cert"; cat "$PREFIX/logs/error.log"; exit 1; }
echo "✓ helper seeded tls-alpn-01 challenge cert"

ACME_OID="1.3.6.1.5.5.7.1.31"

fetch_cert() {
    # extra s_client args; prints the served leaf cert as PEM
    printf '' | openssl s_client -connect "127.0.0.1:$PORT" \
        -servername "$DOMAIN" "$@" 2>/dev/null \
        | openssl x509 2>/dev/null
}

echo "== acme-tls/1 handshake serves the challenge cert =="
ALPN_CERT="$(fetch_cert -alpn acme-tls/1)"
[ -n "$ALPN_CERT" ] || { echo "::error::no cert returned under acme-tls/1"; exit 1; }

ALPN_TEXT="$(printf '%s\n' "$ALPN_CERT" | openssl x509 -text -noout)"
printf '%s\n' "$ALPN_TEXT" | grep -q "$ACME_OID" \
    || { echo "::error::served cert lacks id-pe-acmeIdentifier ($ACME_OID)"; printf '%s\n' "$ALPN_TEXT"; exit 1; }
printf '%s\n' "$ALPN_TEXT" | grep -qi "DNS:$DOMAIN" \
    || { echo "::error::served cert lacks SAN DNS:$DOMAIN"; exit 1; }
echo "✓ acme-tls/1 served a cert with acmeIdentifier + SAN=$DOMAIN"

echo "== normal handshake serves the ordinary (bootstrap) cert, not the challenge =="
NORMAL_TEXT="$(fetch_cert -alpn http/1.1 | openssl x509 -text -noout)"
[ -n "$NORMAL_TEXT" ] || { echo "::error::no cert returned on a normal handshake"; exit 1; }
if printf '%s\n' "$NORMAL_TEXT" | grep -q "$ACME_OID"; then
    echo "::error::normal handshake served the challenge cert"; exit 1
fi
echo "✓ normal handshake did NOT serve the challenge cert"

echo "== normal handshake still negotiates http/1.1 via ALPN =="
ALPN_NEG="$(printf '' | openssl s_client -connect "127.0.0.1:$PORT" \
    -servername "$DOMAIN" -alpn http/1.1 2>/dev/null \
    | grep -i 'ALPN protocol' || true)"
printf '%s\n' "$ALPN_NEG" | grep -qi 'http/1.1' \
    || { echo "::error::ALPN did not negotiate http/1.1 (got: $ALPN_NEG)"; exit 1; }
echo "✓ ALPN negotiated http/1.1 for a normal client"

echo "== mixed-case SNI under acme-tls/1 still serves the challenge cert =="
# The worker lowercases the SNI before ngx_autocert_alpn_get(), so an ACME CA
# (or anything) presenting an upper/mixed-case SNI must still resolve to the
# lowercased store entry the helper seeded.
UPPER_DOMAIN=$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')   # ALPN.EXAMPLE.COM
MIXED_TEXT="$(printf '' | openssl s_client -connect "127.0.0.1:$PORT" \
    -servername "$UPPER_DOMAIN" -alpn acme-tls/1 2>/dev/null \
    | openssl x509 2>/dev/null | openssl x509 -text -noout 2>/dev/null)"
[ -n "$MIXED_TEXT" ] || { echo "::error::no cert returned for mixed-case SNI $UPPER_DOMAIN under acme-tls/1"; exit 1; }
printf '%s\n' "$MIXED_TEXT" | grep -q "$ACME_OID" \
    || { echo "::error::mixed-case SNI $UPPER_DOMAIN did not get the challenge cert (no acmeIdentifier)"; exit 1; }
echo "✓ mixed-case SNI $UPPER_DOMAIN served the tls-alpn-01 challenge cert"

echo "ALL TLS-ALPN-01 SERVE-PATH CHECKS PASSED"
