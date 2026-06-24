#!/usr/bin/env bash
#
# Dual-certificate issuance e2e test — port 80 NEVER used (tls-alpn-01).
#
# Exercises `autocert_key_type p384 rsa2048;` (dual-cert, Phase B): the module
# must issue BOTH an ECDSA and an RSA certificate for the same vhost, each as its
# own ACME order, and store them side by side in one <domain> dir:
#   EC : privkey.pem      / fullchain.pem   (legacy flat names, back-compat)
#   RSA: privkey.rsa.pem  / fullchain.rsa.pem
# Asserts: two distinct "certificate provisioned" lines, both file pairs present,
# each leaf certifies the domain, each cert pubkey == its stored privkey pubkey,
# the EC pair is EC P-384 and the RSA pair is RSA-2048, and the two leaves carry
# DIFFERENT public keys (proving they are genuinely two certs, not one copied).
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-dual-issue}"
NET_NAME="acdual-net-$$"
PEBBLE_NAME="acdual-pebble-$$"
DNS_NAME="acdual-dns-$$"
ORDER_DOMAIN="dual.example.com"
ALPN_PORT=5021                     # nginx listens ssl here; Pebble VA tlsPort

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

echo "== starting challtestsrv =="
DNS_PORT=15475
MGMT_PORT=$((DNS_PORT + 1))
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    -p ${MGMT_PORT}:8055 \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 "" -defaultIPv6 "" >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

for i in $(seq 1 30); do
    if curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/clear-txt" \
            -d '{"host":"_probe.invalid."}' >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "challtestsrv mgmt did not come up"; docker logs "$DNS_NAME"; exit 1; }
done
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"pebble.\",\"addresses\":[\"127.0.0.1\"]}" >/dev/null
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/add-a" \
    -d "{\"host\":\"${ORDER_DOMAIN}.\",\"addresses\":[\"${HOST_IP}\"]}" >/dev/null

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

echo "== starting Pebble =="
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

# NO `listen 80` — the ssl listener on ${ALPN_PORT} is the only one.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    autocert_key_type p384 rsa2048;
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

echo "== start: register account, then issue EC + RSA for ${ORDER_DOMAIN} =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# Wait for TWO provisioned certs (one per keytype). Each keytype is a separate
# order, serialised through the single global order, so the lines arrive in turn.
provisioned=0
for i in $(seq 1 120); do
    provisioned=$( { grep -c 'autocert: certificate provisioned for' \
                  "$PREFIX/logs/error.log" 2>/dev/null || true; } | head -1)
    provisioned=${provisioned:-0}
    [ "$provisioned" -ge 2 ] && break
    if grep -Eq 'autocert: (finalize failed|order poll timed out|order did not become valid|certificate download failed)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

echo "== helper log =="
grep autocert "$PREFIX/logs/error.log" || true

[ "$provisioned" -ge 2 ] \
    || { echo "::error::expected 2 provisioned certs, saw ${provisioned}"
         docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true; exit 1; }
echo "✓ two certificates provisioned (EC + RSA, separate orders)"

EC_KEY="$PREFIX/store/${ORDER_DOMAIN}/privkey.pem"
EC_CHAIN="$PREFIX/store/${ORDER_DOMAIN}/fullchain.pem"
RSA_KEY="$PREFIX/store/${ORDER_DOMAIN}/privkey.rsa.pem"
RSA_CHAIN="$PREFIX/store/${ORDER_DOMAIN}/fullchain.rsa.pem"

for f in "$EC_KEY" "$EC_CHAIN" "$RSA_KEY" "$RSA_CHAIN"; do
    [ -f "$f" ] || { echo "::error::missing $f"; exit 1; }
done
echo "✓ both file pairs present (flat EC + .rsa. RSA) in one dir"

# Each leaf certifies the domain.
for c in "$EC_CHAIN" "$RSA_CHAIN"; do
    openssl x509 -in "$c" -noout -ext subjectAltName 2>/dev/null \
        | grep -q "DNS:${ORDER_DOMAIN}" \
        || { echo "::error::$c SAN does not list ${ORDER_DOMAIN}"; exit 1; }
done
echo "✓ both leaves certify ${ORDER_DOMAIN}"

# Each cert pubkey matches its OWN stored privkey.
ec_cert_pub=$(openssl x509 -in "$EC_CHAIN" -noout -pubkey 2>/dev/null | openssl md5)
ec_key_pub=$(openssl pkey -in "$EC_KEY" -pubout 2>/dev/null | openssl md5)
[ "$ec_cert_pub" = "$ec_key_pub" ] \
    || { echo "::error::EC cert pubkey != stored EC privkey"; exit 1; }
rsa_cert_pub=$(openssl x509 -in "$RSA_CHAIN" -noout -pubkey 2>/dev/null | openssl md5)
rsa_key_pub=$(openssl pkey -in "$RSA_KEY" -pubout 2>/dev/null | openssl md5)
[ "$rsa_cert_pub" = "$rsa_key_pub" ] \
    || { echo "::error::RSA cert pubkey != stored RSA privkey"; exit 1; }
echo "✓ each cert's public key matches its own stored private key"

# The two leaves must be DIFFERENT keys (not the same cert duplicated).
[ "$ec_cert_pub" != "$rsa_cert_pub" ] \
    || { echo "::error::EC and RSA leaves share a public key"; exit 1; }
echo "✓ the two leaves carry distinct public keys"

# Algorithm assertions: EC pair is EC P-384, RSA pair is RSA-2048.
openssl ec -in "$EC_KEY" -noout -check >/dev/null 2>&1 \
    || { echo "::error::flat privkey.pem is not an EC key"; exit 1; }
openssl ec -in "$EC_KEY" -noout -text 2>/dev/null | grep -q 'NIST CURVE: P-384' \
    || { echo "::error::EC key is not P-384"; exit 1; }
echo "✓ flat pair is EC P-384"

openssl rsa -in "$RSA_KEY" -noout -check >/dev/null 2>&1 \
    || { echo "::error::.rsa. privkey is not a valid RSA key"; exit 1; }
rsa_bits=$(openssl rsa -in "$RSA_KEY" -noout -text 2>/dev/null \
    | grep -oE '\(([0-9]+) bit' | grep -oE '[0-9]+' | head -1)
[ "$rsa_bits" = "2048" ] \
    || { echo "::error::.rsa. key is not 2048-bit (got: ${rsa_bits})"; exit 1; }
echo "✓ .rsa. pair is RSA-2048"

echo "✓✓ full dual-certificate issuance verified end-to-end (EC P-384 + RSA-2048)"
