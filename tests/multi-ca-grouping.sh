#!/usr/bin/env bash
#
# multi-CA name grouping (M2, #15) — pure nginx, no CA needed.
#
# Proves the postconfig CA-keyed grouping: enabled server_names across multiple
# vhosts that share the (currently http{}-global) CA collapse into ONE ca_list
# entry holding the deduplicated name set. Asserts the
# "N name(s) enabled for issuance across M CA(s)" log line: 3 names / 1 CA.
# (Per-vhost multiple CAs arrive with M4 SRV-scope directives; M2 builds the
# grouping structure that one-CA world produces a single entry for.)
#
# Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-multica-group}"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Three concrete names across two vhosts, one global CA. The CA is unreachable
# on purpose — we only assert the config-time grouping, not issuance, so the
# driver's later registration failure is irrelevant.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://127.0.0.1:1/dir;
    autocert_store_path $PREFIX/store;
    server {
        listen 8080;
        server_name a.example.com b.example.com;
        autocert on;
    }
    server {
        listen 8081;
        server_name c.example.com;
        autocert on;
    }
}
EOF

echo "== config accepted =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start: postconfig grouping log =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for _ in $(seq 1 20); do
    if grep -q "name(s) enabled for issuance across" "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    sleep 0.3
done
grep "enabled for issuance" "$PREFIX/logs/error.log" | tail -2 || true
[ -n "$ok" ] || { echo "::error::grouping log line not found"; exit 1; }

grep -q "3 name(s) enabled for issuance across 1 CA(s)" "$PREFIX/logs/error.log" \
    || { echo "::error::expected '3 name(s) ... across 1 CA(s)'"; exit 1; }
echo "✓ 3 names across 2 vhosts grouped into 1 CA (deduped)"

echo "ALL MULTI-CA GROUPING CHECKS PASSED"
