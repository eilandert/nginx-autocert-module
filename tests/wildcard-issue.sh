#!/usr/bin/env bash
#
# Wildcard (*.) full issuance + serve e2e test (D4, #16).
#
# Issues a wildcard cert for "*.wc.example.com" via the dns-01 exec hook, then
# proves the serve path presents that ONE cert for multiple distinct subdomain
# SNIs (foo. and bar.) — i.e. the leading-label wildcard match + the shared
# "_wildcard_.wc.example.com" store/cache key both work.
#
# Reuses the dns01-exec-hook harness (pebble-challtestsrv mgmt API publishes
# the TXT). Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-wildcard}"
NET_NAME="ac-wc-net-$$"
PEBBLE_NAME="ac-wc-pebble-$$"
DNS_NAME="ac-wc-dns-$$"
DNS_PORT=15357
MGMT_PORT=8056
BASE_DOMAIN="wc.example.com"
WILDCARD="*.$BASE_DOMAIN"
WILDCARD_SEG="_wildcard_.$BASE_DOMAIN"
TLS_PORT=8443

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    docker rm -f "$PEBBLE_NAME" "$DNS_NAME" >/dev/null 2>&1 || true
    docker network rm "$NET_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store" "$PREFIX/hooks"

docker network create "$NET_NAME" >/dev/null

echo "== pebble-challtestsrv (DNS :53 + mgmt :${MGMT_PORT}; default A -> 127.0.0.1) =="
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    -p ${MGMT_PORT}:8055 \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

for i in $(seq 1 30); do
    if curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/clear-txt" \
            -d '{"host":"_probe.example.com."}' >/dev/null 2>&1; then break; fi
    sleep 1
    [ "$i" = 30 ] && { echo "challtestsrv mgmt did not come up"; docker logs "$DNS_NAME"; exit 1; }
done

cat > "$PREFIX/pebble-config.json" <<EOF
{
  "pebble": {
    "listenAddress": "0.0.0.0:14000",
    "managementListenAddress": "0.0.0.0:15000",
    "certificate": "test/certs/localhost/cert.pem",
    "privateKey": "test/certs/localhost/key.pem",
    "httpPort": 5999,
    "tlsPort": 5998,
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }
}
EOF

echo "== Pebble (validates dns-01 via challtestsrv) =="
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

cat > "$PREFIX/hooks/add.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/set-txt" \
    -d "{\"host\":\"\${1}.\",\"value\":\"\${2}\"}" >/dev/null
EOF
cat > "$PREFIX/hooks/remove.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
curl -sf -X POST "http://127.0.0.1:${MGMT_PORT}/clear-txt" \
    -d "{\"host\":\"\${1}.\"}" >/dev/null
EOF
chmod +x "$PREFIX/hooks/add.sh" "$PREFIX/hooks/remove.sh"

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://pebble:14000/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_ca_certificate $PREFIX/ca.pem;
    autocert_path $PREFIX/store;
    autocert_challenge dns-01;
    autocert_dns_hook_add $PREFIX/hooks/add.sh;
    autocert_dns_hook_remove $PREFIX/hooks/remove.sh;
    autocert_dns_propagation_delay 0;
    autocert_dns_hook_timeout 15;
    server {
        listen ${TLS_PORT} ssl;
        server_name ${WILDCARD};
        autocert on;
    }
}
EOF

echo "== config accepts a wildcard server_name under dns-01 =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start: wildcard dns-01 order for ${WILDCARD} =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

issued=
for i in $(seq 1 90); do
    if grep -q "autocert: certificate provisioned for" "$PREFIX/logs/error.log"; then
        issued=1; break
    fi
    if grep -Eq 'autocert: (ACME order failed|finalize failed|order poll timed out|authorization did not become valid|dns-01 hook .* failed)' \
            "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.5
done

echo "== helper log =="
grep autocert "$PREFIX/logs/error.log" | tail -30 || true

if [ -z "$issued" ]; then
    echo "::error::wildcard certificate was not provisioned"
    docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    exit 1
fi
echo "✓ wildcard certificate provisioned"

# Stored under the fs-safe "_wildcard_." segment, not a literal '*'.
CHAIN="$PREFIX/store/${WILDCARD_SEG}/fullchain.pem"
KEY="$PREFIX/store/${WILDCARD_SEG}/privkey.pem"
[ -f "$CHAIN" ] || { echo "::error::missing $CHAIN (wildcard not stored under _wildcard_.)"; exit 1; }
[ -f "$KEY" ]   || { echo "::error::missing $KEY"; exit 1; }
[ ! -e "$PREFIX/store/${WILDCARD}" ] || { echo "::error::a literal '*' dir was created"; exit 1; }
echo "✓ stored under ${WILDCARD_SEG}/ (no literal '*' path)"

openssl x509 -in "$CHAIN" -noout -ext subjectAltName 2>/dev/null \
    | grep -qF "DNS:${WILDCARD}" \
    || { echo "::error::issued cert SAN does not list ${WILDCARD}"; exit 1; }
echo "✓ issued fullchain.pem certifies ${WILDCARD}"

# Serve path: one wildcard cert presented for distinct subdomain SNIs.
for sub in foo bar; do
    sni="${sub}.${BASE_DOMAIN}"
    san=$(echo | openssl s_client -connect "127.0.0.1:${TLS_PORT}" \
            -servername "$sni" 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
    echo "$san" | grep -qF "DNS:${WILDCARD}" \
        || { echo "::error::SNI $sni was not served the wildcard cert (got: $san)"; exit 1; }
    echo "✓ SNI $sni served the wildcard cert"
done

echo "✓✓ wildcard issuance + multi-subdomain serve verified end-to-end"
