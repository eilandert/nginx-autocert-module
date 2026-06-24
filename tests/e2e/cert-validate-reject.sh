#!/usr/bin/env bash
#
# Negative test for pre-store certificate validation (order.c). Each CI matrix
# case returns a leaf that must be refused before it can replace the store:
# mismatched key, wrong DNS SAN, expired, or not-yet-valid.
#
# The mock CA returns, at /cert, a leaf signed over a DIFFERENT key than the one
# in the order's CSR (simulating a buggy/malicious CA, or a corrupted response).
# Asserts:
#   - the driver logs "is not usable" and does NOT log "issued and stored",
#   - no fullchain.pem is written into the store.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-validate}"
CA_HOST="mockca.example.com"
CA_PORT=14081
DNS_NAME="ac-val-dns-$$"
DNS_PORT=15581
CERT_CASE="${CERT_CASE:-key-mismatch}"
case "$CERT_CASE" in
    key-mismatch|wrong-san|expired|future) ;;
    *) echo "unknown CERT_CASE: $CERT_CASE"; exit 1 ;;
esac
NAME="validate-${CERT_CASE}.example.com"

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
    fi
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null

cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools, datetime, base64
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

BASE = "https://${CA_HOST}:${CA_PORT}"
CA_KEY = serialization.load_pem_private_key(
    open("${PREFIX}/ca-key.pem", "rb").read(), password=None)
CA_CERT = x509.load_pem_x509_certificate(open("${PREFIX}/ca.pem", "rb").read())
NAME = "${NAME}"
CASE = "${CERT_CASE}"
nonces = ("nonce-%d" % i for i in itertools.count())
state = {"chal_done": False, "cert": None}

def b64url_dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def bad_leaf(csr_der):
    csr = x509.load_der_x509_csr(csr_der)
    now = datetime.datetime.utcnow()
    key = csr.public_key()
    name = NAME
    not_before = now - datetime.timedelta(minutes=1)
    not_after = now + datetime.timedelta(days=2)
    if CASE == "key-mismatch":
        key = ec.generate_private_key(ec.SECP256R1()).public_key()
    elif CASE == "wrong-san":
        name = "wrong.example.com"
    elif CASE == "expired":
        not_before = now - datetime.timedelta(days=2)
        not_after = now - datetime.timedelta(days=1)
    elif CASE == "future":
        not_before = now + datetime.timedelta(days=1)
        not_after = now + datetime.timedelta(days=2)
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(CA_CERT.subject)
            .public_key(key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False)
            .sign(CA_KEY, hashes.SHA256()))
    return leaf.public_bytes(serialization.Encoding.PEM)

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
                "newNonce": BASE + "/nonce", "newAccount": BASE + "/acct",
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
            self._send(201, b'{"status":"valid"}', extra={"Location": BASE + "/acct/1"})
        elif self.path == "/order":
            self._send(201, json.dumps({
                "status": "pending", "finalize": BASE + "/finalize",
                "authorizations": [BASE + "/authz"]}).encode(),
                extra={"Location": BASE + "/order/1"})
        elif self.path == "/authz":
            if state["chal_done"]:
                self._send(200, json.dumps({"status": "valid"}).encode())
            else:
                self._send(200, json.dumps({"status": "pending", "challenges": [{
                    "type": "http-01", "status": "pending",
                    "token": "tok-val", "url": BASE + "/chal"}]}).encode())
        elif self.path == "/chal":
            state["chal_done"] = True
            self._send(200, json.dumps({"status": "valid"}).encode())
        elif self.path == "/finalize":
            payload = json.loads(raw.decode())["payload"]
            csr_der = b64url_dec(json.loads(b64url_dec(payload).decode())["csr"])
            state["cert"] = bad_leaf(csr_der)
            self._send(200, json.dumps({
                "status": "valid", "certificate": BASE + "/cert"}).encode())
        elif self.path == "/order/1":
            self._send(200, json.dumps({
                "status": "valid", "certificate": BASE + "/cert"}).encode())
        elif self.path == "/cert":
            self._send(200, state["cert"], ctype="application/pem-certificate-chain")
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
    curl -ksf --resolve ${CA_HOST}:${CA_PORT}:127.0.0.1 \
        --cacert "$PREFIX/ca.pem" https://${CA_HOST}:${CA_PORT}/dir >/dev/null 2>&1 && break
    sleep 0.5
    [ "$i" = 30 ] && { echo "::error::mock CA did not come up"; exit 1; }
done

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
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

"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"
echo "== waiting for the ${CERT_CASE} validation rejection =="
for i in $(seq 1 60); do
    if grep -q "is not usable" "$LOG"; then
        break
    fi
    if grep -q "certificate issued and stored for \"${NAME}\"" "$LOG"; then
        echo "::error::an invalid cert was STORED — validation did not fire"
        exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::no validation rejection logged"; grep autocert "$LOG" | tail -20; exit 1; }
done
echo "✓ ${CERT_CASE} cert rejected ('is not usable' logged)"

# Must not have been stored.
if [ -e "$PREFIX/store/${NAME}/fullchain.pem" ]; then
    echo "::error::fullchain.pem was written despite validation failure"
    exit 1
fi
echo "✓ no fullchain.pem persisted — good cert (if any) preserved"

# Must not have reported success.
if grep -q "certificate issued and stored for \"${NAME}\"" "$LOG"; then
    echo "::error::driver reported success on an invalid cert"
    exit 1
fi
echo "✓ driver did not report success (renewal backoff preserved)"

echo "✓✓ pre-store certificate validation verified"
