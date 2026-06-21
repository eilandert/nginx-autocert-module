#!/usr/bin/env bash
#
# per-vhost multi-CA SRV-scope (M4, #15) — pure nginx, no CA needed.
#
# M4 makes the CA knobs (autocert_ca / _staging / _ca_certificate / _eab_kid /
# _eab_hmac_key) MAIN+SRV scope: a server{} block can override the http{}
# default CA. This test proves the config layer end to end WITHOUT issuance
# (the worker-0 driver stays single-CA until M5, so it only registers against
# ca_list[0]; full dual-CA issuance is multi-ca.sh in M5):
#
#   * inheritance  — a vhost with no autocert_ca uses the http{} global CA
#   * override     — a vhost with its own autocert_ca lands in its own CA group
#   * staging      — autocert_staging at server scope is an override too
#   * grouping     — distinct effective CA URLs => distinct ca_list entries,
#                    asserted via the "N name(s) ... across M CA(s)" log line
#
# Layout: 3 vhosts, 2 distinct effective CAs.
#   CA-A (global default URL): a.example.com  +  c.example.com (inherits)
#   CA-B (per-vhost override):  b.example.com
# => 3 names across 2 CA(s).
#
# Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-multica-srv}"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Both CA URLs are unreachable on purpose — we assert config-time grouping, not
# issuance, so the driver's later registration failure against ca_list[0] is
# irrelevant.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://127.0.0.1:1/ca-a;
    autocert_path $PREFIX/store;

    # vhost A: inherits the http{} default CA (CA-A).
    server {
        listen 8080;
        server_name a.example.com;
        autocert on;
    }

    # vhost B: overrides the CA per-vhost (CA-B) -> its own ca_list entry.
    server {
        listen 8081;
        server_name b.example.com;
        autocert on;
        autocert_ca https://127.0.0.1:2/ca-b;
    }

    # vhost C: no autocert_ca -> inherits CA-A, joins A's group.
    server {
        listen 8082;
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

grep -q "3 name(s) enabled for issuance across 2 CA(s)" "$PREFIX/logs/error.log" \
    || { echo "::error::expected '3 name(s) ... across 2 CA(s)'"; exit 1; }
echo "✓ 3 names / 2 distinct CAs: per-vhost override creates a 2nd CA group"

"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
sleep 0.5

# --- negative: server-scope staging<->ca exclusion must fail config ----------
echo "== negative: server autocert_staging + autocert_ca must fail config =="
cat > "$PREFIX/conf/bad.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/bad.log notice;
events {}
http {
    autocert_path $PREFIX/store;
    server {
        listen 8083;
        server_name d.example.com;
        autocert on;
        autocert_staging on;
        autocert_ca https://127.0.0.1:3/ca-c;
    }
}
EOF

if "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/bad.conf" 2>"$PREFIX/logs/bad.err"; then
    echo "::error::staging+ca at server scope was accepted"; cat "$PREFIX/logs/bad.err"; exit 1
fi
grep -q "mutually exclusive" "$PREFIX/logs/bad.err" \
    || { echo "::error::expected 'mutually exclusive'"; cat "$PREFIX/logs/bad.err"; exit 1; }
echo "✓ server-scope staging<->ca exclusion enforced"

# --- positive: server autocert_staging on overrides a global autocert_ca ------
# (Codex M4 #1) The selector {ca,staging} is a unit: an explicit server staging
# must NOT inherit the global CA and collide — it switches that vhost to the LE
# staging CA, yielding a 2nd CA group.
echo "== positive: server staging overrides global CA (2 CA groups) =="
cat > "$PREFIX/conf/stg.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/stg.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://127.0.0.1:1/ca-a;
    autocert_path $PREFIX/store;
    server {
        listen 8084;
        server_name p.example.com;
        autocert on;
    }
    server {
        listen 8085;
        server_name q.example.com;
        autocert on;
        autocert_staging on;
    }
}
EOF

# The regression this guards: pre-fix, the server inherited the global
# autocert_ca and then tripped the staging<->ca exclusion. Config must now be
# ACCEPTED, with no "mutually exclusive" error.
if ! "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/stg.conf" 2>"$PREFIX/logs/stg.err"; then
    echo "::error::staging override over a global autocert_ca was rejected"
    cat "$PREFIX/logs/stg.err"; exit 1
fi
if grep -q "mutually exclusive" "$PREFIX/logs/stg.err"; then
    echo "::error::staging override collided with inherited global CA"
    cat "$PREFIX/logs/stg.err"; exit 1
fi
echo "✓ server staging overrides global autocert_ca cleanly (no selector collision)"

# --- negative: same name under two different CAs must fail config (M5 LOW) -----
# One server_name issues ONE certificate from ONE CA. Two vhosts that both list
# the same name but pin different CAs is ambiguous (which CA signs the single
# cert?) — reject at parse instead of silently keeping the first CA.
echo "== negative: same server_name under two different CAs must fail config =="
cat > "$PREFIX/conf/dup.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/dup.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_path $PREFIX/store;
    server {
        listen 8086;
        server_name dup.example.com;
        autocert on;
        autocert_ca https://127.0.0.1:1/ca-a;
    }
    server {
        listen 8087;
        server_name dup.example.com;
        autocert on;
        autocert_ca https://127.0.0.1:2/ca-b;
    }
}
EOF

if "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/dup.conf" 2>"$PREFIX/logs/dup.err"; then
    echo "::error::same name under two CAs was accepted"; cat "$PREFIX/logs/dup.err"; exit 1
fi
grep -q "claimed by two vhosts with different CAs" "$PREFIX/logs/dup.err" \
    || { echo "::error::expected 'claimed by two vhosts with different CAs'"; \
         cat "$PREFIX/logs/dup.err"; exit 1; }
echo "✓ same name under conflicting CAs rejected at config time"

# --- positive: same name under the SAME CA across two vhosts is fine -----------
echo "== positive: same server_name under the SAME CA is the harmless dup =="
cat > "$PREFIX/conf/same.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/same.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://127.0.0.1:1/ca-a;
    autocert_path $PREFIX/store;
    server { listen 8088; server_name sds.example.com; autocert on; }
    server { listen 8089; server_name sds.example.com; autocert on; }
}
EOF
if ! "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/same.conf" 2>"$PREFIX/logs/same.err"; then
    echo "::error::same name under the same CA was rejected"; cat "$PREFIX/logs/same.err"; exit 1
fi
echo "✓ same name under one CA accepted (deduped, no false conflict)"

echo "ALL MULTI-CA SRV-SCOPE CHECKS PASSED"
