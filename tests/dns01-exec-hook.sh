#!/usr/bin/env bash
#
# dns-01 exec-hook full issuance e2e test (D3, #16) — port 80/TLS VA NEVER used.
#
# Proves the dns-01 provider path end to end: the driver computes the TXT value,
# runs the operator add-hook (fork+execve) to publish it, waits the propagation
# delay, the CA validates the authorization by a real DNS TXT lookup, the cert
# is finalized + downloaded + stored, and the remove-hook runs on order finish.
#
# DNS is served by pebble-challtestsrv: its mgmt API (:8055) lets the hook
# publish/clear TXT records dynamically, and Pebble is pointed at its DNS (:53)
# with `-dnsserver`. No HTTP-01 / TLS-ALPN-01 listener is involved at all.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-dns01-hook}"
NET_NAME="ac-dns01h-net-$$"
PEBBLE_NAME="ac-dns01h-pebble-$$"
DNS_NAME="ac-dns01h-dns-$$"
DNS_PORT=15356
MGMT_PORT=8055
ORDER_DOMAIN="dns01hook.example.com"

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
# defaultIPv4 127.0.0.1 makes "pebble" resolve to the host loopback where Pebble
# is published, so the nginx ACME client can reach https://pebble:14000/dir.
# http01/https01/tlsalpn01 challenge responders are disabled (dns-01 only).
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    -p ${MGMT_PORT}:8055 \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null
DNS_CONTAINER_IP=$(docker inspect -f \
    '{{ (index .NetworkSettings.Networks "'"$NET_NAME"'").IPAddress }}' "$DNS_NAME")

# mgmt API reachable from the host (the hook scripts curl it).
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

# Provider hooks. argv = { hook, _acme-challenge.<domain>, <txt> }. challtestsrv
# wants a fully-qualified host (trailing dot).
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
        listen 8080;
        server_name ${ORDER_DOMAIN};
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start: dns-01 order with exec hooks for ${ORDER_DOMAIN} =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

issued=
for i in $(seq 1 90); do
    if grep -q 'autocert: certificate provisioned for' "$PREFIX/logs/error.log"; then
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
    echo "::error::certificate was not provisioned via dns-01 exec hook"
    echo "== pebble log =="; docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    echo "== challtestsrv log =="; docker logs "$DNS_NAME" 2>&1 | tail -20 || true
    exit 1
fi
echo "✓ certificate provisioned via dns-01 (add-hook published, CA validated)"

# The add-hook must have actually fired (fork+execve path).
grep -q 'autocert: dns-01 exec add hook' "$PREFIX/logs/error.log" \
    || { echo "::error::add-hook never executed"; exit 1; }
echo "✓ dns-01 add-hook executed"

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

# The remove-hook must run on order finish (unpublish), cleaning up the TXT.
removed=
for i in $(seq 1 20); do
    if grep -q 'autocert: dns-01 exec remove hook' "$PREFIX/logs/error.log"; then
        removed=1; break
    fi
    sleep 0.5
done
[ -n "$removed" ] || { echo "::error::remove-hook never executed on order finish"; exit 1; }
echo "✓ dns-01 remove-hook executed (TXT cleaned up)"

echo "✓✓ full dns-01 exec-hook issuance verified end-to-end"
