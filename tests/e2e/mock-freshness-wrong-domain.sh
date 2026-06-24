#!/usr/bin/env bash
#
# M2 regression — renewal freshness must reject a wrong-domain stored leaf.
#
# The scheduler decides a name is "fresh" (not due) from the stored fullchain's
# key family + notAfter. Before this fix it did NOT check that the leaf actually
# covers the configured name, so a wrong-domain cert with the right key family
# and an unexpired notAfter (e.g. a segment collision or a restored backup) read
# as fresh forever — while serve.c's X509_check_host rejects it, wedging the
# vhost with no working cert until expiry. name_due now mirrors serve: a stored
# leaf that does not cover the name is treated as due and reissued.
#
# This test pre-seeds the store for NAME with a self-signed EC leaf that covers a
# DIFFERENT domain (right key family, unexpired), points the module at a mock CA,
# and asserts the driver logs the wrong-domain reissue and replaces the cert with
# one that actually covers NAME. Pre-fix the wrong cert would be kept (fresh) and
# no order would run.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-fresh-wrongdom}"
CA_HOST="mockca.example.com"
CA_PORT=14037
DNS_NAME="ac-fresh-dns-$$"
DNS_PORT=15489
NAME="freshdom.example.com"
WRONG="other-domain.example.com"

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store/$NAME"

# Mock CA's own cert + a CA signing key.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

# Pre-seed the store: an EC P-384 leaf (matching the default key family) that
# covers the WRONG domain, unexpired. Pre-fix this reads as fresh; post-fix the
# identity check fails and the name is reissued.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -nodes \
    -keyout "$PREFIX/store/$NAME/privkey.pem" \
    -out    "$PREFIX/store/$NAME/fullchain.pem" \
    -days 2 -subj "/CN=$WRONG" -addext "subjectAltName=DNS:$WRONG" >/dev/null 2>&1
chmod 600 "$PREFIX/store/$NAME/privkey.pem"

echo "== pre-seeded a wrong-domain ($WRONG) EC leaf at the store path for $NAME =="
openssl x509 -in "$PREFIX/store/$NAME/fullchain.pem" -noout -ext subjectAltName

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null

# ---- mock ACME server (straight happy path) --------------------------------
cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools, base64, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

BASE = "https://${CA_HOST}:${CA_PORT}"
CA_KEY = serialization.load_pem_private_key(
    open("${PREFIX}/ca-key.pem", "rb").read(), password=None)
CA_CERT = x509.load_pem_x509_certificate(open("${PREFIX}/ca.pem", "rb").read())
NAME = "${NAME}"
nonces = ("nonce-%d" % i for i in itertools.count())

def b64url_dec(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def make_leaf(csr_der):
    csr = x509.load_der_x509_csr(csr_der)
    now = datetime.datetime.utcnow()
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)]))
            .issuer_name(CA_CERT.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(NAME)]), False)
            .sign(CA_KEY, hashes.SHA256()))
    return leaf.public_bytes(serialization.Encoding.PEM)

state = {"leaf": None, "chal_done": False}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Replay-Nonce", next(nonces))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path == "/dir":
            self._send(200, json.dumps({
                "newNonce": BASE + "/nonce",
                "newAccount": BASE + "/acct",
                "newOrder": BASE + "/order"}).encode())
        elif self.path == "/nonce":
            self._send(204)
        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

    do_HEAD = do_GET

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""

        if self.path == "/nonce":
            self._send(204)
        elif self.path == "/acct":
            self._send(201, b'{"status":"valid"}',
                       extra={"Location": BASE + "/acct/1"})
        elif self.path == "/order":
            self._send(201, json.dumps({
                "status": "pending",
                "finalize": BASE + "/finalize",
                "authorizations": [BASE + "/authz"],
            }).encode(), extra={"Location": BASE + "/order/1"})
        elif self.path == "/authz":
            if state["chal_done"]:
                self._send(200, json.dumps({"status": "valid"}).encode())
            else:
                self._send(200, json.dumps({
                    "status": "pending",
                    "challenges": [{
                        "type": "http-01",
                        "status": "pending",
                        "token": "mock-token-freshdom",
                        "url": BASE + "/chal",
                    }],
                }).encode())
        elif self.path == "/chal":
            state["chal_done"] = True
            self._send(200, json.dumps({"status": "valid"}).encode())
        elif self.path == "/finalize":
            payload = json.loads(raw.decode())["payload"]
            csr = b64url_dec(json.loads(b64url_dec(payload).decode())["csr"])
            state["leaf"] = make_leaf(csr)
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": BASE + "/cert",
            }).encode())
        elif self.path == "/order/1":
            if state["leaf"] is not None:
                self._send(200, json.dumps({
                    "status": "valid",
                    "certificate": BASE + "/cert",
                }).encode())
            else:
                self._send(200, json.dumps({"status": "ready"}).encode())
        elif self.path == "/cert":
            self._send(200, state["leaf"],
                       ctype="application/pem-certificate-chain")
        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("${PREFIX}/ca.pem", "${PREFIX}/ca-key.pem")
srv = HTTPServer(("0.0.0.0", ${CA_PORT}), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PYEOF

echo "== starting mock ACME CA on :$CA_PORT =="
python3 "$PREFIX/mockca.py" &
MOCK_PID=$!
for i in $(seq 1 30); do
    if curl -ksf --resolve ${CA_HOST}:${CA_PORT}:127.0.0.1 \
        --cacert "$PREFIX/ca.pem" https://${CA_HOST}:${CA_PORT}/dir >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
    [ "$i" = 30 ] && { echo "::error::mock CA did not come up"; exit 1; }
done

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the root-owned store
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://${CA_HOST}:${CA_PORT}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_resolver_timeout 5s;
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    server { listen 80; server_name ${NAME}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

# 1) The scheduler must flag the wrong-domain stored cert and reissue.
echo "== waiting for the wrong-domain reissue line =="
for i in $(seq 1 60); do
    if grep -q "stored cert does not cover this name" "$LOG"; then
        break
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::scheduler did not detect the wrong-domain leaf"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ scheduler detected the wrong-domain leaf and marked it due"

# 2) Issuance must complete with a cert that actually covers NAME.
echo "== waiting for issuance to complete =="
for i in $(seq 1 60); do
    if grep -q "certificate issued and stored for \"${NAME}\"" "$LOG"; then
        break
    fi
    if grep -Eq 'autocert: (finalize failed|order poll timed out|order did not become valid|certificate download failed|ACME order failed)' "$LOG"; then
        echo "::error::order aborted"; grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::issuance did not complete"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ certificate issued and stored"

# 3) The replacement leaf must cover NAME, not the wrong domain.
SAN="$(openssl x509 -in "$PREFIX/store/$NAME/fullchain.pem" -noout -ext subjectAltName 2>/dev/null || true)"
echo "stored SAN now: $SAN"
printf '%s\n' "$SAN" | grep -q "DNS:$NAME" \
    || { echo "::error::replacement leaf does not cover $NAME"; exit 1; }
if printf '%s\n' "$SAN" | grep -q "DNS:$WRONG"; then
    echo "::error::wrong-domain leaf still present"; exit 1
fi
echo "✓ replacement leaf covers $NAME (wrong-domain leaf gone)"

echo "✓✓ M2 verified: a wrong-domain stored leaf is detected as stale and reissued"
