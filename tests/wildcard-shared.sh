#!/usr/bin/env bash
#
# autocert_wildcard shared-cert e2e test (D5, #16).
#
# Proves the autocert_wildcard directive: several CONCRETE-name vhosts
# (foo. and bar.wc.example.com), each on its own listener, share ONE wildcard
# certificate declared once at http{} level with `autocert_wildcard
# *.wc.example.com;` — without any wildcard in server_name. Asserts:
#   1. exactly the wildcard "*.wc.example.com" is issued (stored under
#      "_wildcard_.wc.example.com"),
#   2. SUPPRESSION: no per-subdomain cert dir (foo./bar.) is created — the
#      concrete server_names covered by the wildcard are NOT issued separately,
#   3. each subdomain's own listener serves that one wildcard cert per-SNI.
#
# This is the autocert_wildcard counterpart to wildcard-issue.sh (which drives
# the legacy wildcard-in-server_name path). Reuses the same pebble +
# pebble-challtestsrv dns-01 harness.
#
# Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-wildcard-shared}"
NET_NAME="ac-wcs-net-$$"
PEBBLE_NAME="ac-wcs-pebble-$$"
DNS_NAME="ac-wcs-dns-$$"
DNS_PORT=15358
MGMT_PORT=8057
BASE_DOMAIN="wc.example.com"
WILDCARD="*.$BASE_DOMAIN"
WILDCARD_SEG="_wildcard_.$BASE_DOMAIN"
FOO_PORT=8443
BAR_PORT=8444

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

# The whole point: NO wildcard in server_name. The two vhosts carry concrete
# names; one http-level autocert_wildcard covers both and is the only cert
# issued. (foo. and bar. are single-label subdomains of the wildcard, so they
# are suppressed — served from the wildcard, not issued.)
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
    autocert_wildcard ${WILDCARD};

    server {
        listen ${FOO_PORT} ssl;
        server_name foo.${BASE_DOMAIN};
        autocert on;
    }
    server {
        listen ${BAR_PORT} ssl;
        server_name bar.${BASE_DOMAIN};
        autocert on;
    }
}
EOF

echo "== config accepts concrete vhosts + http-level autocert_wildcard =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start: shared wildcard dns-01 order for ${WILDCARD} =="
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
    echo "::error::shared wildcard certificate was not provisioned"
    docker logs "$PEBBLE_NAME" 2>&1 | tail -40 || true
    exit 1
fi
echo "✓ wildcard certificate provisioned"

# Stored under the fs-safe "_wildcard_." segment.
CHAIN="$PREFIX/store/${WILDCARD_SEG}/fullchain.pem"
KEY="$PREFIX/store/${WILDCARD_SEG}/privkey.pem"
[ -f "$CHAIN" ] || { echo "::error::missing $CHAIN (wildcard not stored)"; exit 1; }
[ -f "$KEY" ]   || { echo "::error::missing $KEY"; exit 1; }
echo "✓ stored under ${WILDCARD_SEG}/"

# SUPPRESSION: the concrete subdomains must NOT have their own cert dirs — they
# are covered by the wildcard and served from it, never issued separately.
for sub in foo bar; do
    [ ! -e "$PREFIX/store/${sub}.${BASE_DOMAIN}" ] \
        || { echo "::error::${sub}.${BASE_DOMAIN} got its own cert dir — suppression failed (it should be served from the wildcard)"; exit 1; }
done
echo "✓ suppression: no per-subdomain cert issued (foo./bar. served from the wildcard)"

# Exactly one name was issued (the wildcard). "provisioned for" lines == 1.
PROV=$(grep -c "autocert: certificate provisioned for" "$PREFIX/logs/error.log" || true)
[ "$PROV" = "1" ] || { echo "::error::expected exactly 1 provisioned cert, got $PROV"; exit 1; }
echo "✓ exactly one certificate issued for the whole subdomain set"

openssl x509 -in "$CHAIN" -noout -ext subjectAltName 2>/dev/null \
    | grep -qF "DNS:${WILDCARD}" \
    || { echo "::error::issued cert SAN does not list ${WILDCARD}"; exit 1; }
echo "✓ issued fullchain.pem certifies ${WILDCARD}"

# Serve path: each subdomain's OWN listener presents the shared wildcard cert.
serve_check() {
    local sni="$1" port="$2"
    local san
    san=$(echo | openssl s_client -connect "127.0.0.1:${port}" \
            -servername "$sni" 2>/dev/null \
            | openssl x509 -noout -ext subjectAltName 2>/dev/null || true)
    echo "$san" | grep -qF "DNS:${WILDCARD}" \
        || { echo "::error::SNI $sni (:$port) was not served the wildcard cert (got: $san)"; exit 1; }
    echo "✓ SNI $sni (:$port) served the shared wildcard cert"
}
serve_check "foo.${BASE_DOMAIN}" "$FOO_PORT"
serve_check "bar.${BASE_DOMAIN}" "$BAR_PORT"

echo "✓✓ autocert_wildcard: one shared wildcard cert, concrete names suppressed, served per-SNI"
