#!/usr/bin/env bash
#
# dns-01 order-flow plumbing (D2, #16) — NO provider hook yet.
#
# Proves the dns-01 branch of the order state machine runs end to end up to the
# publish step: config accepts `autocert_challenge dns-01`, the driver selects
# the dns-01 challenge, computes the TXT value base64url(SHA256(keyauth)), logs
# the record to publish, and arms the propagation-delay timer. Full CA
# validation against a live DNS is exercised in D3 (dns01-exec-hook.sh), where
# the exec hook actually publishes the TXT — here publishing is a stub, so the
# CA would not validate; we assert only the plumbing up to publish.
#
# Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR (defaults beside it).

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-dns01-order}"
NET_NAME="ac-dns01-net-$$"
PEBBLE_NAME="ac-dns01-pebble-$$"
DNS_NAME="ac-dns01-dns-$$"
DNS_PORT=15355
ORDER_DOMAIN="dns01.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

docker network create "$NET_NAME" >/dev/null
HOST_IP=$(docker network inspect "$NET_NAME" -f '{{ (index .IPAM.Config 0).Gateway }}')

echo "== dnsmasq (pebble -> 127.0.0.1; order domain -> host) =="
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/pebble/127.0.0.1 \
    --address=/${ORDER_DOMAIN}/"${HOST_IP}" >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

cat > "$PREFIX/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 80,
    "tlsPort": 5001,
    "externalAccountBindingRequired": false
  }
}
EOF

echo "== Pebble (DNS via dnsmasq) =="
docker run -d --name "$PEBBLE_NAME" --network "$NET_NAME" \
    -p 14000:14000 -p 15000:15000 \
    -e PEBBLE_VA_NOSLEEP=1 \
    -v "$PREFIX/pebble-config.json:/test/config/pebble-config.json:ro" \
    ghcr.io/letsencrypt/pebble:latest \
    -config /test/config/pebble-config.json \
    -dnsserver "${DNS_CONTAINER_IP}:53" >/dev/null

for i in $(seq 1 30); do
    if curl -ksf https://127.0.0.1:14000/dir >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "Pebble did not come up"; docker logs "$PEBBLE_NAME"; exit 1; }
done
docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$PREFIX/ca.pem"

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
    autocert_challenge dns-01;
    # D3 requires both hooks for dns-01; /bin/true is a no-op stub so the order
    # still reaches (and logs) the publish-TXT step without a real DNS provider.
    autocert_dns_hook_add /bin/true;
    autocert_dns_hook_remove /bin/true;
    server {
        listen 8080;
        server_name ${ORDER_DOMAIN};
    }
}
EOF

echo "== config accepts autocert_challenge dns-01 =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start: account + dns-01 order reaches publish-TXT =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for i in $(seq 1 60); do
    if grep -q "dns-01 challenge for \"${ORDER_DOMAIN}\": publish TXT" \
            "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    sleep 0.5
done
grep autocert "$PREFIX/logs/error.log" | tail -20 || true
[ -n "$ok" ] || { echo "::error::dns-01 order did not reach the publish-TXT step"; exit 1; }
echo "✓ dns-01 order selected the challenge + computed the TXT value"

# The logged TXT value must be a 43-char base64url SHA-256 digest (no padding).
txt=$(sed -n 's/.*publish TXT _acme-challenge\.[^ ]* = "\([^"]*\)".*/\1/p' \
        "$PREFIX/logs/error.log" | head -1)
case "$txt" in
    *[!A-Za-z0-9_-]*) echo "::error::TXT not base64url: '$txt'"; exit 1;;
    "")               echo "::error::could not parse TXT value"; exit 1;;
esac
if [ "${#txt}" -ne 43 ]; then
    echo "::error::TXT length ${#txt}, expected 43 (base64url SHA-256)"; exit 1
fi
echo "✓ TXT value is a 43-char base64url SHA-256 digest"

echo "ALL DNS-01 ORDER PLUMBING CHECKS PASSED"
