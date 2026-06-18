#!/usr/bin/env bash
#
# ACME renewal + multi-name scheduler e2e test (M8).
#
# Builds on order-authz.sh. Two things M8 adds over M6:
#   1. The helper provisions EVERY collected server_name, not just the first.
#   2. A periodic scheduler reissues a certificate once it is inside its
#      renew_before window (now >= notAfter - renew_before).
#
# We drive both:
#   - Two server{} blocks (two domains) -> assert BOTH get a cert on first run.
#   - autocert_renew_before is set absurdly large (larger than the Pebble cert
#     lifetime) so every stored cert is permanently "inside" its renew window.
#     A reload spawns a fresh helper whose initial scan therefore reissues both
#     domains. We capture each leaf's serial before the reload and assert it
#     changes after — i.e. a genuine reissue landed atomically in the store and
#     the per-SNI serve path would hot-reload it (M7).
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

PREFIX="${PREFIX:-/tmp/ac-renewal}"
NET_NAME="ac-net-$$"
PEBBLE_NAME="ac-pebble-$$"
DNS_NAME="ac-dns-$$"
DOMAIN_A="a.example.com"
DOMAIN_B="b.example.com"

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

DNS_PORT=15353
docker run -d --name "$DNS_NAME" --network "$NET_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/pebble/127.0.0.1 \
    --address=/${DOMAIN_A}/${HOST_IP} \
    --address=/${DOMAIN_B}/${HOST_IP} >/dev/null
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

# renew_before far exceeds the Pebble cert lifetime => every cert is always
# inside its renew window, so a fresh helper scan reissues it.
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
    autocert_renew_before 9999d;
    server { listen 80; server_name ${DOMAIN_A}; }
    server { listen 80; server_name ${DOMAIN_B}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

CHAIN_A="$PREFIX/store/${DOMAIN_A}/fullchain.pem"
CHAIN_B="$PREFIX/store/${DOMAIN_B}/fullchain.pem"

wait_for_cert() {
    local f="$1" i
    for i in $(seq 1 120); do
        [ -f "$f" ] && openssl x509 -in "$f" -noout -serial 2>/dev/null && return 0
        sleep 0.5
    done
    return 1
}

echo "== start: provision BOTH domains =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

SERIAL_A1=$(wait_for_cert "$CHAIN_A") || { echo "::error::${DOMAIN_A} not provisioned"; grep autocert "$PREFIX/logs/error.log" || true; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
SERIAL_B1=$(wait_for_cert "$CHAIN_B") || { echo "::error::${DOMAIN_B} not provisioned"; grep autocert "$PREFIX/logs/error.log" || true; docker logs "$PEBBLE_NAME" 2>&1 | tail -40; exit 1; }
echo "✓ both domains provisioned (multi-name): A=$SERIAL_A1 B=$SERIAL_B1"

# Reload -> fresh helper -> initial scan finds both inside the renew window
# (renew_before huge) -> reissues both. New serials prove a real reissue.
echo "== reload: force renewal scan =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload

renewed() {
    local f="$1" old="$2" i cur
    for i in $(seq 1 120); do
        cur=$(openssl x509 -in "$f" -noout -serial 2>/dev/null || true)
        [ -n "$cur" ] && [ "$cur" != "$old" ] && { echo "$cur"; return 0; }
        sleep 0.5
    done
    return 1
}

SERIAL_A2=$(renewed "$CHAIN_A" "$SERIAL_A1") || { echo "::error::${DOMAIN_A} not renewed (serial unchanged)"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
SERIAL_B2=$(renewed "$CHAIN_B" "$SERIAL_B1") || { echo "::error::${DOMAIN_B} not renewed (serial unchanged)"; grep autocert "$PREFIX/logs/error.log" | tail -30; exit 1; }
echo "✓ both domains reissued inside renew window: A=$SERIAL_A2 B=$SERIAL_B2"

# Renewed cert must still be a valid leaf that certifies its domain and whose
# pubkey matches the (freshly issued) stored key — i.e. the atomic swap kept the
# key/chain pair consistent.
for d in "$DOMAIN_A" "$DOMAIN_B"; do
    key="$PREFIX/store/$d/privkey.pem"
    chain="$PREFIX/store/$d/fullchain.pem"
    openssl x509 -in "$chain" -noout -ext subjectAltName 2>/dev/null \
        | grep -q "DNS:${d}" || { echo "::error::renewed cert SAN missing $d"; exit 1; }
    cpub=$(openssl x509 -in "$chain" -noout -pubkey 2>/dev/null | openssl md5)
    kpub=$(openssl pkey -in "$key" -pubout 2>/dev/null | openssl md5)
    [ "$cpub" = "$kpub" ] || { echo "::error::renewed cert pubkey != stored key for $d"; exit 1; }
done
echo "✓ renewed key/chain pairs are consistent and certify their domains"

# --- Negative cases (M9): staleness detection -------------------------------
# Switch to a SMALL renew_before so a healthy stored cert is NOT due — that lets
# us prove the scheduler reissues ONLY when the stored fullchain is unusable
# (corrupt / missing / a symlink), and leaves a healthy cert untouched.
echo "== restart with small renew_before (healthy certs not due) =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop
sleep 1
sed -i 's/autocert_renew_before 9999d;/autocert_renew_before 60s;/' \
    "$PREFIX/conf/nginx.conf"
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# Healthy certs must survive the initial scan unchanged (control).
SERIAL_A3=$(openssl x509 -in "$CHAIN_A" -noout -serial)
SERIAL_B3=$(openssl x509 -in "$CHAIN_B" -noout -serial)
sleep 6
[ "$(openssl x509 -in "$CHAIN_A" -noout -serial)" = "$SERIAL_A3" ] \
    || { echo "::error::healthy ${DOMAIN_A} reissued though not due"; exit 1; }
[ "$(openssl x509 -in "$CHAIN_B" -noout -serial)" = "$SERIAL_B3" ] \
    || { echo "::error::healthy ${DOMAIN_B} reissued though not due"; exit 1; }
echo "✓ healthy certs not reissued under small renew_before (control)"

# Corrupt A's fullchain, remove B's entirely, then reload (fresh helper scans
# at once). A: parse fails -> NGX_ERROR -> due. B: open ENOENT -> NGX_DECLINED
# -> due. Both must be reissued into a fresh, valid cert.
echo "== corrupt A + remove B, reload =="
echo "-----BEGIN CERTIFICATE-----\nnot a real cert\n-----END CERTIFICATE-----" \
    > "$CHAIN_A"
rm -rf "$PREFIX/store/${DOMAIN_B}"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload

SERIAL_A4=$(renewed "$CHAIN_A" "$SERIAL_A3") \
    || { echo "::error::corrupt ${DOMAIN_A} not reissued"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
SERIAL_B4=$(wait_for_cert "$CHAIN_B") \
    || { echo "::error::missing ${DOMAIN_B} not re-provisioned"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
openssl x509 -in "$CHAIN_A" -noout -ext subjectAltName 2>/dev/null \
    | grep -q "DNS:${DOMAIN_A}" || { echo "::error::reissued ${DOMAIN_A} invalid"; exit 1; }
echo "✓ corrupt + missing fullchain both trigger reissue: A=$SERIAL_A4 B=$SERIAL_B4"

# Replace A's fullchain with a symlink: the O_NOFOLLOW open must refuse to
# follow it (NGX_ERROR -> due) and reissue a real regular file in its place.
echo "== symlink A's fullchain, reload =="
SERIAL_A5=$(openssl x509 -in "$CHAIN_A" -noout -serial)
rm -f "$CHAIN_A"
ln -s /etc/hostname "$CHAIN_A"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload
for i in $(seq 1 120); do
    if [ ! -L "$CHAIN_A" ] && cur=$(openssl x509 -in "$CHAIN_A" -noout -serial 2>/dev/null) \
       && [ -n "$cur" ] && [ "$cur" != "$SERIAL_A5" ]; then
        break
    fi
    sleep 0.5
    [ "$i" = 120 ] && { echo "::error::symlinked ${DOMAIN_A} not reissued as a regular file"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
done
[ -L "$CHAIN_A" ] && { echo "::error::${DOMAIN_A} fullchain still a symlink"; exit 1; }
echo "✓ symlinked fullchain refused (O_NOFOLLOW) and reissued as a regular file"

echo "✓✓ M8 renewal + multi-name + M9 staleness negatives verified end-to-end"
