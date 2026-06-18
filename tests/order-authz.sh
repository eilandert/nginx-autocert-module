#!/usr/bin/env bash
#
# ACME order + authorization e2e test (M6a).
#
# Builds on acme-directory.sh: brings up Pebble + dnsmasq, registers an account,
# then drives the full order flow for one domain —
#   newOrder -> fetch authz -> http-01 token -> keyauth -> publish to the
#   challenge store -> POST the challenge -> poll the authorization until valid.
#
# The crux is that Pebble's validation authority (VA), running in the Pebble
# container, must fetch
#   http://<domain>/.well-known/acme-challenge/<token>
# from OUR nginx. So:
#   - nginx listens on :80 (the :80 worker serves the M5 challenge handler),
#   - dnsmasq maps <domain> to the host IP reachable from the Pebble container,
#   - Pebble is told to use that dnsmasq for DNS and to hit port 80.
# We then assert the helper logs the authorization reaching "valid".
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

PREFIX="${PREFIX:-/tmp/ac-order-authz}"
NET_NAME="ac-net-$$"
PEBBLE_NAME="ac-pebble-$$"
DNS_NAME="ac-dns-$$"
ORDER_DOMAIN="le.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# A user-defined bridge so we know its gateway = the host address the Pebble
# container uses to reach nginx on the host's :80.
docker network create "$NET_NAME" >/dev/null
HOST_IP=$(docker network inspect "$NET_NAME" \
    -f '{{ (index .IPAM.Config 0).Gateway }}')
echo "== host IP reachable from containers: $HOST_IP =="

echo "== starting dnsmasq (pebble -> 127.0.0.1 view for the helper; order domain -> host) =="
# dnsmasq serves two views via published port:
#   - the helper (on the host) resolves 'pebble' to 127.0.0.1 (Pebble's published port)
#   - Pebble (in-container) resolves the order domain to the host gateway
# A single address mapping the order domain to the host IP is enough for the VA;
# the helper reaches Pebble through the published 14000 with host 'pebble'.
DNS_PORT=15353
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/pebble/127.0.0.1 \
    --address=/${ORDER_DOMAIN}/${HOST_IP} >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

# Pebble's baked test config validates http-01 on port 5002, not 80. Override
# with our own config so the VA fetches our token on port 80 (where nginx
# listens). The cert/key paths match the baked image layout.
cat > "$PREFIX/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 80,
    "tlsPort": 5001,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

echo "== starting Pebble (VA -> http :80 at the order domain, DNS via dnsmasq) =="
docker run -d --name "$PEBBLE_NAME" --network "$NET_NAME" \
    -p 14000:14000 -p 15000:15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -e PEBBLE_WFE_NONCEREJECT=0 \
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
    autocert_path $PREFIX/store;
    server {
        listen 80;
        server_name ${ORDER_DOMAIN};
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start: register account, then run order for ${ORDER_DOMAIN} =="
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
echo "✓ authorization reached valid (http-01 served, VA fetched our token)"

# The order is now ready to finalize — the success line carries the order URL.
if ! grep -q 'autocert: order ready to finalize' "$PREFIX/logs/error.log"; then
    echo "::error::order-ready line missing"
    exit 1
fi
echo "✓ order ready to finalize (order/finalize URLs captured for M6b)"
