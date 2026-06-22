#!/usr/bin/env bash
#
# TOCTOU hardening test: the store commit is fd-pinned (O_DIRECTORY|O_NOFOLLOW
# container fd + *at() leaf ops), so a symlink planted at a store path component
# can never redirect a write outside the store. This test plants such symlinks
# BEFORE issuance and asserts:
#   (1) secure layout: a symlink at <store>/<domain> pointing outside the store
#       is refused ("not a directory") — no key/cert is written through it, and
#       the escape target stays empty.
#   (2) certbot layout: a symlink at <store>/live pointing outside the store is
#       refused when the container dir fd is opened O_NOFOLLOW — the escape
#       target stays empty.
#
# A full real ACME issuance is not needed: the refusal happens at the store-
# commit step, which runs only after the cert is downloaded. So we drive a clean
# mock issuance (like store-certbot.sh) and assert the escape dir is never
# written and the live cert is NOT placed through the symlink.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-symswap}"
CA_HOST="mockca.example.com"
CA_PORT=14071
DNS_NAME="ac-ss-dns-$$"
DNS_PORT=15571
NAME="symswap.example.com"

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store" "$PREFIX/escape"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/leaf-key.pem" -out "$PREFIX/leaf.pem" -days 2 -nodes \
    -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1
cp "$PREFIX/leaf.pem" "$PREFIX/chain.pem"

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/${CA_HOST}/127.0.0.1 >/dev/null

cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools, base64, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

BASE = "https://${CA_HOST}:${CA_PORT}"
# Sign the leaf over the CSR pubkey so it passes the driver's leaf<->key check;
# the point of this test is that the planted SYMLINK is what refuses the store,
# not cert validation.
CA_KEY = serialization.load_pem_private_key(
    open("${PREFIX}/ca-key.pem", "rb").read(), password=None)
CA_CERT = x509.load_pem_x509_certificate(open("${PREFIX}/ca.pem", "rb").read())
NAME = "${NAME}"
nonces = ("nonce-%d" % i for i in itertools.count())
state = {"chal_done": False, "leaf": None}

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
                        "type": "http-01", "status": "pending",
                        "token": "tok-ss", "url": BASE + "/chal",
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
                "status": "valid", "certificate": BASE + "/cert"}).encode())
        elif self.path == "/order/1":
            self._send(200, json.dumps({
                "status": "valid", "certificate": BASE + "/cert"}).encode())
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

run_server() {
    # $1 = store mode ("secure" or "certbot"); $2 = store path.
    local store_path="${2:-$PREFIX/store}"
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
    autocert_store_path $store_path;
    autocert_store_layout $1;
    server { listen 80; server_name ${NAME}; }
}
EOF
    "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
}

wait_for_refusal() {
    # The commit refuses the symlinked component; issuance never reports stored.
    # We assert the escape dir stays empty and the server logs the refusal.
    local log="$PREFIX/logs/error.log"
    for i in $(seq 1 60); do
        if grep -Eq 'autocert: (store path|") .* is not a directory|open store dir .* failed|staging .* is not a directory' "$log"; then
            return 0
        fi
        if grep -q "certificate issued and stored for \"${NAME}\"" "$log"; then
            return 1   # stored despite the symlink — BUG
        fi
        sleep 0.5
    done
    return 2
}

#
# (1) secure layout: plant <store>/<domain> as a symlink to the escape dir.
#
echo "== secure layout: symlink at <store>/${NAME} -> escape =="
rm -f "$PREFIX/logs/error.log"
ln -s "$PREFIX/escape" "$PREFIX/store/${NAME}"
run_server secure

if ! wait_for_refusal; then
    rc=$?
    if [ "$rc" = 1 ]; then
        echo "::error::secure: cert was stored THROUGH the planted symlink"
    else
        echo "::error::secure: no refusal logged within timeout"
    fi
    grep autocert "$PREFIX/logs/error.log" | tail -20
    exit 1
fi
echo "✓ secure: symlinked <store>/${NAME} refused (not dereferenced)"

# Nothing was written into the escape target.
if [ -n "$(ls -A "$PREFIX/escape" 2>/dev/null)" ]; then
    echo "::error::secure: files written into escape dir through the symlink:"
    ls -la "$PREFIX/escape"
    exit 1
fi
echo "✓ secure: escape dir is empty — no write escaped the store"

cp "$PREFIX/logs/error.log" "$PREFIX/logs/error-secure.log"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
sleep 1

#
# (2) certbot layout: plant <store>/live as a symlink to the escape dir. The
# container dir fd is opened O_NOFOLLOW, so this is refused before any per-domain
# write.
#
echo "== certbot layout: symlink at <store>/live -> escape =="
rm -rf "$PREFIX/store" "$PREFIX/escape"
mkdir -p "$PREFIX/store" "$PREFIX/escape"
rm -f "$PREFIX/logs/error.log"
ln -s "$PREFIX/escape" "$PREFIX/store/live"
run_server certbot

if ! wait_for_refusal; then
    rc=$?
    if [ "$rc" = 1 ]; then
        echo "::error::certbot: cert was stored THROUGH the planted live symlink"
    else
        echo "::error::certbot: no refusal logged within timeout"
    fi
    grep autocert "$PREFIX/logs/error.log" | tail -20
    exit 1
fi
echo "✓ certbot: symlinked <store>/live refused (container fd O_NOFOLLOW)"

if [ -n "$(ls -A "$PREFIX/escape" 2>/dev/null)" ]; then
    echo "::error::certbot: files written into escape dir through the live symlink:"
    ls -la "$PREFIX/escape"
    exit 1
fi
echo "✓ certbot: escape dir is empty — no write escaped the store"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
sleep 1

#
# (3) ancestor component: <prefix>/parent is a symlink. This must be rejected
# before the driver creates .driver.lock, accounts/, or any certificate path;
# O_NOFOLLOW on only the final <store> component would otherwise follow it.
#
echo "== ancestor component: <prefix>/parent -> escape =="
rm -rf "$PREFIX/store" "$PREFIX/escape" "$PREFIX/parent"
mkdir -p "$PREFIX/escape"
ln -s "$PREFIX/escape" "$PREFIX/parent"
rm -f "$PREFIX/logs/error.log"
run_server secure "$PREFIX/parent/store"

for i in $(seq 1 30); do
    if grep -q 'cannot open/create store dir' "$PREFIX/logs/error.log"; then
        break
    fi
    sleep 0.2
    [ "$i" = 30 ] && {
        echo "::error::ancestor symlink was not refused by the driver"
        grep autocert "$PREFIX/logs/error.log" | tail -20
        exit 1
    }
done

if [ -n "$(ls -A "$PREFIX/escape" 2>/dev/null)" ]; then
    echo "::error::ancestor symlink redirected lock/account/certificate writes:"
    ls -la "$PREFIX/escape"
    exit 1
fi
echo "✓ ancestor symlink refused before any store write escaped"

echo "✓✓ store symlink-swap (all path components) hardening verified"
