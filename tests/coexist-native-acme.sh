#!/usr/bin/env bash
#
# Coexistence test: this module's `autocert` running in the SAME instance as
# Angie's native `acme` / `acme_client` directives (which create the implicit
# "@acme" server block). The README promises coexistence; this exercises it.
#
# `angie -t` only — no network/docker. Asserts:
#   - the config is ACCEPTED (exit 0): autocert's postconfig walks every server,
#     including the disabled-for-autocert "@acme" implicit ssl server, without
#     crashing or wrongly rejecting it;
#   - autocert still enumerates its issuable name(s);
#   - the run does NOT die on a signal (the original prod bug was a SIGSEGV in
#     serve_init at this exact point — see memory issues.md 2026-06-22).
#
# Skips cleanly when SERVER_BIN has no native `acme` directive (mainline nginx,
# or an angie built without --with-http_acme_module) so it is safe everywhere.
#
# Inputs (env):
#   SERVER_BIN    - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR - build dir holding objs/*.so (defaults to dir-of-SERVER_BIN/..)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-coexist}"
rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Native acme is angie-only. Detect it; skip otherwise (mainline nginx etc.).
if ! "$SERVER_BIN" -V 2>&1 | grep -q -- '--with-http_acme_module'; then
    echo "SKIP coexist-native-acme: SERVER_BIN built without native acme module"
    exit 0
fi

# Self-signed leaf so the autocert vhost has a literal ssl_certificate fallback
# (the prod scenario — a real cert kept while autocert takes over per-SNI).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/dummy.key" -out "$PREFIX/dummy.crt" \
    -days 1 -nodes -subj /CN=dummy >/dev/null 2>&1

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
pid $PREFIX/angie.pid;
events { worker_connections 64; }
http {
    access_log off;
    client_body_temp_path $PREFIX/body;
    proxy_temp_path $PREFIX/proxy;
    fastcgi_temp_path $PREFIX/fcgi;
    uwsgi_temp_path $PREFIX/uwsgi;
    scgi_temp_path $PREFIX/scgi;
    resolver 127.0.0.1:53 valid=10s ipv6=off;

    # Angie native ACME — creates the implicit "@acme" server block.
    acme_client le https://acme-staging-v02.api.letsencrypt.org/directory;

    # This module.
    autocert_store_path $PREFIX/store;
    autocert_contact mailto:admin@example.com;

    # vhost driven by native acme.
    server {
        listen 127.0.0.1:8443 ssl;
        server_name native.example.com;
        acme le;
        ssl_certificate $PREFIX/dummy.crt;
        ssl_certificate_key $PREFIX/dummy.key;
    }

    # vhost driven by this module's autocert, alongside native acme.
    server {
        listen 127.0.0.1:8444 ssl;
        server_name auto.example.com;
        autocert on;
        ssl_certificate $PREFIX/dummy.crt;
        ssl_certificate_key $PREFIX/dummy.key;
    }
}
EOF

out=""; rc=0
out=$("$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1) || rc=$?

# The autocert-names notice fires in postconfig, after error_log is parsed, so
# depending on the build it lands on stderr OR in the log file — check both.
log="$(cat "$PREFIX/logs/error.log" 2>/dev/null || true)"
both="$out
$log"

if [ "$rc" -ge 128 ]; then
    echo "::error::coexist-native-acme: server died on signal $((rc-128)) (SIGSEGV=11 -> the original ABI/coexistence crash regressed)"
    printf '%s\n' "$both" | sed 's/^/    /'
    exit 1
fi
if [ "$rc" -ne 0 ]; then
    echo "::error::coexist-native-acme: -t FAILED (exit $rc) with native acme + autocert"
    printf '%s\n' "$both" | sed 's/^/    /'
    exit 1
fi
if ! printf '%s' "$both" | grep -q 'autocert:.*name(s) enabled for issuance'; then
    echo "::error::coexist-native-acme: autocert did not enumerate names"
    printf '%s\n' "$both" | sed 's/^/    /'
    exit 1
fi

echo "✓ coexist-native-acme: native acme + autocert accepted, names enumerated, no crash"
