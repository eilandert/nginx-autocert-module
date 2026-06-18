#!/usr/bin/env bash
#
# M5 HTTP-01 challenge serve test (no network / no docker).
#
# Seeds a token->keyauth into the shared challenge store via the test-only
# autocert_test_challenge directive (the helper inserts it at startup), then
# fetches /.well-known/acme-challenge/<token> from a worker on :80-style port
# and asserts the exact key authorization comes back, that an unknown token is
# 404, and that a token with a trailing path segment is declined (404).
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

PREFIX="${PREFIX:-/tmp/ac-http01}"
PORT="${AC_TEST_PORT:-8088}"
TOKEN="evaGxfADs6pSRb2LMJ7rzMrXXX0123456789abcdefg"
KEYAUTH="$TOKEN.9jg46WB3rR_AHD-EBXdN7cBkH1WOu0tA3M9fm21mqTI"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert_path $PREFIX/store;
    autocert_test_challenge $TOKEN "$KEYAUTH";
    server {
        listen $PORT;
        server_name a.example.com;
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# wait for the helper to seed the token
for _ in $(seq 1 30); do
    grep -q 'seeded test challenge token' "$PREFIX/logs/error.log" && break
    sleep 0.3
done
grep autocert "$PREFIX/logs/error.log" || true

echo "== fetch valid token =="
got=$(curl -fsS "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN")
if [ "$got" != "$KEYAUTH" ]; then
    echo "::error::wrong keyauth: got '$got' want '$KEYAUTH'"
    exit 1
fi
echo "✓ served exact key authorization"

echo "== unknown token -> 404 =="
code=$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$PORT/.well-known/acme-challenge/doesnotexist")
[ "$code" = "404" ] || { echo "::error::unknown token gave $code, want 404"; exit 1; }
echo "✓ unknown token 404"

echo "== token with extra path segment -> 404 =="
code=$(curl -s -o /dev/null -w '%{http_code}' \
    "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN/extra")
[ "$code" = "404" ] || { echo "::error::nested path gave $code, want 404"; exit 1; }
echo "✓ nested path declined"

echo "== Content-Length matches keyauth =="
clen=$(curl -fsS -D - -o /dev/null \
    "http://127.0.0.1:$PORT/.well-known/acme-challenge/$TOKEN" \
    | awk 'tolower($1)=="content-length:"{gsub(/\r/,"",$2); print $2}')
[ "$clen" = "${#KEYAUTH}" ] || {
    echo "::error::Content-Length $clen != ${#KEYAUTH}"; exit 1; }
echo "✓ Content-Length correct"

echo "✓ M5 HTTP-01 challenge serve path verified"
