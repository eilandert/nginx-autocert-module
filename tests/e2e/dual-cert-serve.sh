#!/usr/bin/env bash
#
# Dual-certificate SERVE e2e test — no ACME, no docker, no root.
#
# Proves the Phase B serve path (serve.c cert_cb 2-slot install): with BOTH an
# ECDSA and an RSA cert on disk for one name, the worker installs both on the
# connection and OpenSSL picks the leaf matching the client's offered signature
# algorithms. We drop two self-signed pairs into one store dir:
#   EC : privkey.pem      / fullchain.pem      (slot 0, legacy flat names)
#   RSA: privkey.rsa.pem  / fullchain.rsa.pem  (slot 1)
# then handshake forcing EC-only vs RSA-only sigalgs and assert the served leaf's
# public-key algorithm each time. Also asserts an unconstrained client gets a
# valid leaf, and that with ONLY the RSA pair present the RSA cert still serves
# (single-slot path unaffected).
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-dual-serve}"
PORT="${AC_TEST_PORT:-8463}"
DOMAIN="dual-serve.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store/$DOMAIN"

# Self-signed EC P-384 pair into the flat (slot 0) names.
gen_ec() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \
        -keyout "$PREFIX/store/$DOMAIN/privkey.pem" \
        -out    "$PREFIX/store/$DOMAIN/fullchain.pem" \
        -days 2 -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
    chmod 600 "$PREFIX/store/$DOMAIN/privkey.pem"
}
# Self-signed RSA-2048 pair into the .rsa. (slot 1) names.
gen_rsa() {
    openssl req -x509 -newkey rsa:2048 -nodes \
        -keyout "$PREFIX/store/$DOMAIN/privkey.rsa.pem" \
        -out    "$PREFIX/store/$DOMAIN/fullchain.rsa.pem" \
        -days 2 -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
    chmod 600 "$PREFIX/store/$DOMAIN/privkey.rsa.pem"
}

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log info;
events {}
http {
    autocert_store_path $PREFIX/store;
    # Both keytypes enabled so serving installs both slots. The serve path only
    # installs config-enabled slots, so this http-scope list must name both.
    autocert_key_type p384 rsa2048;
    server {
        listen $PORT ssl;
        server_name $DOMAIN;
        autocert on;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

# Served leaf's public-key algorithm for a given client constraint.
# $1 = SNI ; $2.. = extra openssl s_client args (e.g. -sigalgs ...)
served_algo() {
    local sni="$1" out; shift
    # s_client may exit nonzero on a missing close_notify even after a complete
    # handshake; capture tolerantly so `set -euo pipefail` can't abort the test,
    # and let the parse below decide success. A no-match grep is fine (-> empty).
    out=$(echo | openssl s_client -connect "127.0.0.1:$PORT" -servername "$sni" \
                  -tls1_2 "$@" 2>/dev/null || true)
    printf '%s\n' "$out" | openssl x509 -noout -text 2>/dev/null \
        | { grep -i 'Public Key Algorithm' || true; } | head -1 || true
}

echo "== start with BOTH EC and RSA pairs on disk =="
gen_ec
gen_rsa
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do
    echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | grep -q CONNECTED && break
    sleep 0.2
done
sleep 1.2   # defeat the 1s stat throttle so the first probe loads both slots

# EC-only client: offer only ECDSA sigalgs -> must be served the EC leaf.
ec_algo=$(served_algo "$DOMAIN" -sigalgs "ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256")
echo "EC-only client saw: ${ec_algo:-<none>}"
echo "$ec_algo" | grep -qi 'id-ecPublicKey\|EC Public Key' \
    || { echo "::error::EC-only client was not served an EC leaf"; exit 1; }
echo "✓ EC-only client served the ECDSA certificate"

# RSA-only client: offer only RSA sigalgs -> must be served the RSA leaf.
rsa_algo=$(served_algo "$DOMAIN" -sigalgs "rsa_pss_rsae_sha256:rsa_pkcs1_sha256")
echo "RSA-only client saw: ${rsa_algo:-<none>}"
echo "$rsa_algo" | grep -qi 'rsaEncryption' \
    || { echo "::error::RSA-only client was not served an RSA leaf"; exit 1; }
echo "✓ RSA-only client served the RSA certificate"

# Unconstrained client: must get SOME valid leaf for the domain.
any_out=$(echo | openssl s_client -connect "127.0.0.1:$PORT" -servername "$DOMAIN" \
        2>/dev/null || true)
any=$(printf '%s\n' "$any_out" | openssl x509 -noout -subject 2>/dev/null || true)
case "$any" in
    *CN*=*"$DOMAIN") echo "✓ unconstrained client served a valid $DOMAIN leaf ($any)";;
    *) echo "::error::unconstrained client got no valid leaf (got '$any')"; exit 1;;
esac

echo "== single-slot: remove EC pair, only RSA remains =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
# Wait for the old worker to release the port before restarting, else the new
# process can't bind and the stale (EC-cached) old process answers the probe.
for _ in $(seq 1 50); do
    echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | grep -q CONNECTED || break
    sleep 0.2
done
rm -f "$PREFIX/store/$DOMAIN/privkey.pem" "$PREFIX/store/$DOMAIN/fullchain.pem"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do
    echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | grep -q CONNECTED && break
    sleep 0.2
done
sleep 1.2
only_rsa=$(served_algo "$DOMAIN")
echo "RSA-only-on-disk client saw: ${only_rsa:-<none>}"
echo "$only_rsa" | grep -qi 'rsaEncryption' \
    || { echo "::error::with only the RSA pair on disk, RSA leaf was not served"; exit 1; }
echo "✓ with only the RSA pair on disk, the RSA cert serves (empty EC slot ok)"

# --- audit follow-up H2: a wrong-family flat fullchain.pem is NOT served as EC ---
# A pre-dual-cert single-RSA deployment wrote its RSA leaf to the FLAT names
# (slot 0 / EC). After upgrade the EC slot must reject that file by key family,
# leaving the EC slot empty so only the real RSA leaf (slot 1) serves.
echo "== wrong-family flat fullchain.pem (RSA in the EC slot) is ignored =="
cleanup
for _ in $(seq 1 50); do
    echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | grep -q CONNECTED || break
    sleep 0.2
done
# Put an RSA pair under the FLAT (EC) names, plus the real RSA pair under .rsa.
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$PREFIX/store/$DOMAIN/privkey.pem" \
    -out    "$PREFIX/store/$DOMAIN/fullchain.pem" \
    -days 2 -subj "/CN=$DOMAIN" -addext "subjectAltName=DNS:$DOMAIN" >/dev/null 2>&1
chmod 600 "$PREFIX/store/$DOMAIN/privkey.pem"
gen_rsa
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do
    echo | openssl s_client -connect "127.0.0.1:$PORT" 2>/dev/null | grep -q CONNECTED && break
    sleep 0.2
done
sleep 1.2
# An EC-only client must NOT be handed the flat RSA file as if it were an EC
# leaf. The EC slot rejects the wrong-family file, so it stays empty; with only
# an RSA leaf installed and no EC leaf, an ECDSA-only client shares no usable
# certificate and the handshake fails (no leaf returned). The pass condition is
# therefore: the EC-only client sees the EC *algorithm* on no leaf. We assert
# the served key algorithm is never EC (it is either nothing, or — were the bug
# present — RSA, which is still a fail because the flat RSA file would have been
# installed into the EC slot and served to this EC-only probe).
ec_wrong=$(served_algo "$DOMAIN" -sigalgs "ecdsa_secp384r1_sha384:ecdsa_secp256r1_sha256")
echo "EC-only client (flat file is RSA) saw algo: ${ec_wrong:-<none>}"
if echo "$ec_wrong" | grep -qi 'rsaEncryption'; then
    echo "::error::EC-only client was served the flat RSA file (wrong-family not rejected)"; exit 1
fi
if echo "$ec_wrong" | grep -qi 'id-ecPublicKey\|EC Public Key'; then
    echo "::error::EC-only client was served an EC leaf, but no valid EC cert exists"; exit 1
fi
echo "✓ flat RSA fullchain ignored by the EC slot (EC-only client gets no leaf)"
# The real RSA leaf still serves for an RSA-only client.
rsa_ok=$(served_algo "$DOMAIN" -sigalgs "rsa_pss_rsae_sha256:rsa_pkcs1_sha256")
echo "$rsa_ok" | grep -qi 'rsaEncryption' \
    || { echo "::error::real RSA leaf not served alongside the ignored flat file"; exit 1; }
echo "✓ real .rsa. leaf still serves while the flat RSA file is ignored"

echo "✓✓ dual-certificate serving verified (EC-only -> EC, RSA-only -> RSA, single-slot, wrong-family ignored)"
