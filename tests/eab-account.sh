#!/usr/bin/env bash
#
# External Account Binding e2e (M15, RFC 8555 §7.3.4).
#
# Brings up Pebble in EAB-required mode and asserts the worker-0 driver can
# register an ACME account ONLY when it sends a valid externalAccountBinding —
# i.e. the EAB protected header, the account-key JWK payload and the HMAC-SHA256
# signature are all built correctly. Three runs:
#   1. positive: correct kid + hmac  -> account registered.
#   2. negative (runtime): no EAB     -> CA rejects, registration fails.
#   3. negative (config):  only one of kid/hmac -> nginx -t fails.
#
# Pebble validates EAB against the kid->key map seeded from its config's
# "externalAccountMACKeys"; the config value is base64url and Pebble decodes it
# to raw bytes (db.AddExternalAccountKeyByID). Our directive takes the SAME
# base64url string and decodes it the same way, so the HMAC keys match. We seed
# kid-1 with a fixed base64url key below.
#
# Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR (defaults beside it).

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-eab}"
PEBBLE_NAME="ac-pebble-eab-$$"
DNS_NAME="ac-dns-eab-$$"
DNS_PORT=15354

EAB_KID="kid-1"
EAB_HMAC="zWNDZM6eQGHWpSRTPal5eIUYFTu7EajVIoguysqZ9wG44nMEtx3MUAsUDkMTQ12W"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf"

# Pebble config with EAB required + a seeded MAC key for our kid.
cat > "$PREFIX/conf/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5002,
    "tlsPort": 5001,
    "externalAccountBindingRequired": true,
    "externalAccountMACKeys": {
      "$EAB_KID": "$EAB_HMAC"
    }
  }
}
EOF

echo "== starting Pebble (EAB required) =="
docker run -d --name "$PEBBLE_NAME" -p 14000:14000 -p 15000:15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -v "$PREFIX/conf/pebble-config.json:/test/config/pebble-config.json:ro" \
    ghcr.io/letsencrypt/pebble:latest >/dev/null

echo "== starting dnsmasq (resolves 'pebble' -> 127.0.0.1) =="
docker run -d --name "$DNS_NAME" -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/pebble/127.0.0.1 >/dev/null

for i in $(seq 1 30); do
    if curl -ksf https://127.0.0.1:14000/dir >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "Pebble did not come up"; docker logs "$PEBBLE_NAME"; exit 1; }
done

docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PREFIX/ca.pem"

write_conf() {  # $1 = extra http{} lines
    cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_certificate $PREFIX/ca.pem;
    autocert_path $PREFIX/store;
$1
    server {
        listen 8080;
        server_name a.example.com;
    }
}
EOF
}

# ---------------------------------------------------------------- positive
echo "== positive: register with EAB =="
write_conf "    autocert_eab_kid \"$EAB_KID\";
    autocert_eab_hmac_key \"$EAB_HMAC\";"
mkdir -p "$PREFIX/store"
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
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
grep autocert "$PREFIX/logs/error.log" || true
[ -n "$ok" ] || { echo "::error::EAB account did not register"; exit 1; }
echo "✓ account registered with valid EAB"

# ---------------------------------------------------------------- negative (runtime)
echo "== negative: EAB-required CA rejects an unbound account =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
sleep 1
write_conf ""        # no EAB directives
rm -rf "$PREFIX/store"; mkdir -p "$PREFIX/store"
: > "$PREFIX/logs/error.log"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

bad=
for i in $(seq 1 30); do
    if grep -q 'autocert: ACME account registration failed' "$PREFIX/logs/error.log"; then
        bad=1; break
    fi
    if grep -q 'autocert: ACME account registered, kid' "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done
grep autocert "$PREFIX/logs/error.log" || true
[ -n "$bad" ] || { echo "::error::EAB-required CA accepted an unbound account"; exit 1; }
echo "✓ unbound account correctly rejected by the EAB-required CA"

# ---------------------------------------------------------------- negative (config)
echo "== negative: kid without hmac must fail config =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
write_conf "    autocert_eab_kid \"$EAB_KID\";"   # hmac missing
if "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>"$PREFIX/cfg.err"; then
    echo "::error::config with only autocert_eab_kid was accepted"
    cat "$PREFIX/cfg.err"
    exit 1
fi
grep -q 'must both be set' "$PREFIX/cfg.err" \
    || { echo "::error::wrong/missing both-or-neither error"; cat "$PREFIX/cfg.err"; exit 1; }
echo "✓ both-or-neither validation enforced"

echo "ALL EAB CHECKS PASSED"
