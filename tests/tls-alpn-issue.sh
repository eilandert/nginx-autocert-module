#!/usr/bin/env bash
#
# tls-alpn-01 full issuance e2e test (M10c) — port 80 NEVER used.
#
# Like order-authz.sh, but the order is driven with `autocert_challenge
# tls-alpn-01;`. The helper builds the RFC 8737 challenge certificate, publishes
# it into the ALPN store (M10b), and the worker serves it at the TLS handshake
# when Pebble's VA connects with ALPN "acme-tls/1" + SNI=<domain>. Pebble is told
# to validate tls-alpn-01 on a high `tlsPort` (no :80 listener anywhere), proving
# the port-80-free path. We then assert the authorization reaches valid, the
# certificate is provisioned and stored, and the helper actually served the
# challenge cert over the ALPN path.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

PROC_SO="$NGX_BUILD_DIR/objs/ngx_autocert_process_module.so"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$PROC_SO" ] || { echo "missing $PROC_SO"; exit 1; }
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-tls-alpn-issue}"
NET_NAME="acalpn-net-$$"
PEBBLE_NAME="acalpn-pebble-$$"
DNS_NAME="acalpn-dns-$$"
ORDER_DOMAIN="alpn.example.com"
ALPN_PORT=5001                     # nginx listens ssl here; Pebble VA tlsPort

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

docker network create "$NET_NAME" >/dev/null
HOST_IP=$(docker network inspect "$NET_NAME" \
    -f '{{ (index .IPAM.Config 0).Gateway }}')
echo "== host IP reachable from containers: $HOST_IP =="

echo "== starting dnsmasq (pebble -> 127.0.0.1 for the helper; order domain -> host) =="
DNS_PORT=15453
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/pebble/127.0.0.1 \
    --address=/${ORDER_DOMAIN}/${HOST_IP} >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

# Validate tls-alpn-01 on ${ALPN_PORT}. httpPort is set to a closed port (5999)
# to prove http-01 is never used; the VA only dials tlsPort for this challenge.
cat > "$PREFIX/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5999,
    "tlsPort": ${ALPN_PORT},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

echo "== starting Pebble (VA -> tls-alpn-01 on :${ALPN_PORT} at the order domain) =="
docker run -d --name "$PEBBLE_NAME" --network "$NET_NAME" \
    -p 14000:14000 -p 15000:15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -v "$PREFIX/pebble-config.json:/test/config/pebble-config.json:ro" \
    ghcr.io/letsencrypt/pebble:latest \
    -config /test/config/pebble-config.json \
    -dnsserver "${DNS_CONTAINER_IP}:53" -strict >/dev/null

for i in $(seq 1 30); do
    if curl -ksf https://127.0.0.1:14000/dir >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "Pebble did not come up"; docker logs "$PEBBLE_NAME"; exit 1; }
done

docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PREFIX/ca.pem"

# NOTE: NO `listen 80` anywhere — the ssl listener on ${ALPN_PORT} is the only one.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_certificate $PREFIX/ca.pem;
    autocert_path $PREFIX/store;
    autocert_challenge tls-alpn-01;
    server {
        listen ${ALPN_PORT} ssl;
        server_name ${ORDER_DOMAIN};
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start: register account, then run tls-alpn-01 order for ${ORDER_DOMAIN} =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for i in $(seq 1 60); do
    if grep -q 'autocert: authorization for .* is valid' "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    if grep -Eq 'autocert: ACME order failed|authorization poll timed out|authorization did not become valid' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

echo "== helper log =="
grep autocert "$PREFIX/logs/error.log" || true

if [ -z "$ok" ]; then
    echo "::error::authorization did not reach valid"
    echo "== pebble log =="
    docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    exit 1
fi
echo "✓ authorization reached valid (tls-alpn-01 served, VA used :${ALPN_PORT})"

# The ALPN serve path must have actually fired (M10b worker log line).
grep -q 'served tls-alpn-01 challenge cert' "$PREFIX/logs/error.log" \
    || { echo "::error::worker never served a tls-alpn-01 challenge cert"; exit 1; }
echo "✓ worker served the tls-alpn-01 challenge cert at the handshake"

issued=
for i in $(seq 1 60); do
    if grep -q 'autocert: certificate provisioned for' "$PREFIX/logs/error.log"; then
        issued=1; break
    fi
    if grep -Eq 'autocert: (finalize failed|order poll timed out|order did not become valid|certificate download failed|ACME order failed)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

if [ -z "$issued" ]; then
    echo "::error::certificate was not provisioned"
    docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    exit 1
fi
echo "✓ certificate provisioned (finalize -> poll -> download -> store)"

KEY="$PREFIX/store/${ORDER_DOMAIN}/privkey.pem"
CHAIN="$PREFIX/store/${ORDER_DOMAIN}/fullchain.pem"
[ -f "$KEY" ]   || { echo "::error::missing $KEY"; exit 1; }
[ -f "$CHAIN" ] || { echo "::error::missing $CHAIN"; exit 1; }

openssl x509 -in "$CHAIN" -noout -ext subjectAltName 2>/dev/null \
    | grep -q "DNS:${ORDER_DOMAIN}" \
    || { echo "::error::issued cert SAN does not list ${ORDER_DOMAIN}"; exit 1; }
echo "✓ issued fullchain.pem certifies ${ORDER_DOMAIN}"

CERT_PUB=$(openssl x509 -in "$CHAIN" -noout -pubkey 2>/dev/null | openssl md5)
KEY_PUB=$(openssl pkey -in "$KEY" -pubout 2>/dev/null | openssl md5)
[ "$CERT_PUB" = "$KEY_PUB" ] || { echo "::error::cert pubkey != stored privkey"; exit 1; }
echo "✓ issued certificate public key matches the stored private key"

echo "✓✓ full tls-alpn-01 issuance verified end-to-end (no port 80)"
