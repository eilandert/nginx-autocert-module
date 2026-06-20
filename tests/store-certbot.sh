#!/usr/bin/env bash
#
# certbot store layout test: `autocert_store certbot;` issues into the flat
# certbot live/ layout, <path>/live/<domain>/{privkey,cert,chain,fullchain}.pem,
# and the serve path reads from there.
#
# A mock ACME CA drives a clean full issuance (no 400s), returning a 2-cert
# chain (leaf + one intermediate) so cert.pem / chain.pem are both non-empty.
# Asserts:
#   - all four files exist under <path>/live/<domain>/ with the right modes,
#   - privkey.pem is the EC key, fullchain == cert + chain (leaf + intermediate),
#   - cert.pem is exactly the leaf, chain.pem the intermediate,
#   - the secure-layout dir <path>/<domain>/ was NOT created.
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

PREFIX="${PREFIX:-/tmp/ac-certbot}"
CA_HOST="mockca.example.com"
CA_PORT=14041
DNS_NAME="ac-cb-dns-$$"
DNS_PORT=15493
NAME="certbot.example.com"

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

# Build a 2-cert "fullchain": a leaf + a distinct intermediate (both
# self-signed standalone certs are fine — the helper stores the chain verbatim
# and never verifies it). cert.pem must equal the first, chain.pem the second.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/leaf-key.pem" -out "$PREFIX/leaf.pem" -days 2 -nodes \
    -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/inter-key.pem" -out "$PREFIX/inter.pem" -days 2 -nodes \
    -subj "/CN=Mock Intermediate" >/dev/null 2>&1
cat "$PREFIX/leaf.pem" "$PREFIX/inter.pem" > "$PREFIX/chain.pem"

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/${CA_HOST}/127.0.0.1 >/dev/null

cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = "https://${CA_HOST}:${CA_PORT}"
CHAIN = open("${PREFIX}/chain.pem", "rb").read()
nonces = ("nonce-%d" % i for i in itertools.count())
state = {"chal_done": False}

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
        if n:
            self.rfile.read(n)
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
                        "token": "tok-certbot", "url": BASE + "/chal",
                    }],
                }).encode())
        elif self.path == "/chal":
            state["chal_done"] = True
            self._send(200, json.dumps({"status": "valid"}).encode())
        elif self.path == "/finalize":
            self._send(200, json.dumps({
                "status": "valid", "certificate": BASE + "/cert"}).encode())
        elif self.path == "/order/1":
            self._send(200, json.dumps({
                "status": "valid", "certificate": BASE + "/cert"}).encode())
        elif self.path == "/cert":
            self._send(200, CHAIN, ctype="application/pem-certificate-chain")
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
load_module $PROC_SO;
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://${CA_HOST}:${CA_PORT}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_resolver_timeout 5s;
    autocert_ca_certificate $PREFIX/ca.pem;
    autocert_path $PREFIX/store;
    autocert_store certbot;
    server { listen 80; server_name ${NAME}; }
}
EOF

echo "== config test (certbot store must be accepted) =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"
echo "== waiting for issuance =="
for i in $(seq 1 60); do
    grep -q "certificate issued and stored for \"${NAME}\"" "$LOG" && break
    if grep -Eq 'autocert: (finalize failed|order did not become valid|certificate download failed|ACME order failed)' "$LOG"; then
        echo "::error::issuance failed"; grep autocert "$LOG" | tail -20; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::issuance did not complete"; grep autocert "$LOG" | tail -20; exit 1; }
done
echo "✓ issuance complete"

LIVE="$PREFIX/store/live/${NAME}"
for f in privkey.pem cert.pem chain.pem fullchain.pem; do
    [ -f "$LIVE/$f" ] || { echo "::error::missing $LIVE/$f"; ls -la "$PREFIX/store" "$LIVE" 2>&1; exit 1; }
done
echo "✓ all four certbot files present under live/${NAME}/"

# The secure-layout dir must NOT exist (we wrote the certbot layout instead).
[ ! -e "$PREFIX/store/${NAME}" ] \
    || { echo "::error::secure-layout dir $PREFIX/store/${NAME} also created"; exit 1; }
echo "✓ no secure-layout dir created"

# Modes: privkey 600, the rest 644.
KMODE=$(stat -c '%a' "$LIVE/privkey.pem")
[ "$KMODE" = "600" ] || { echo "::error::privkey.pem mode $KMODE != 600"; exit 1; }
for f in cert.pem chain.pem fullchain.pem; do
    m=$(stat -c '%a' "$LIVE/$f")
    [ "$m" = "644" ] || { echo "::error::$f mode $m != 644"; exit 1; }
done
echo "✓ modes: privkey 0600, cert/chain/fullchain 0644"

# privkey is an EC key.
openssl pkey -in "$LIVE/privkey.pem" -noout -text 2>/dev/null | grep -qi 'NIST CURVE\|ASN1 OID' \
    || { echo "::error::privkey.pem is not a valid EC key"; exit 1; }
echo "✓ privkey.pem is an EC key"

# cert.pem == leaf (one cert), chain.pem == intermediate (one cert),
# fullchain == cert + chain.
nc_cert=$(grep -c 'BEGIN CERTIFICATE' "$LIVE/cert.pem")
nc_chain=$(grep -c 'BEGIN CERTIFICATE' "$LIVE/chain.pem")
nc_full=$(grep -c 'BEGIN CERTIFICATE' "$LIVE/fullchain.pem")
[ "$nc_cert" = "1" ]  || { echo "::error::cert.pem has $nc_cert certs, want 1"; exit 1; }
[ "$nc_chain" = "1" ] || { echo "::error::chain.pem has $nc_chain certs, want 1"; exit 1; }
[ "$nc_full" = "2" ]  || { echo "::error::fullchain.pem has $nc_full certs, want 2"; exit 1; }
echo "✓ cert.pem=1 chain.pem=1 fullchain.pem=2 certs"

# cert.pem's subject is the leaf (CN=$NAME); chain.pem's is the intermediate.
openssl x509 -in "$LIVE/cert.pem" -noout -subject 2>/dev/null | grep -q "$NAME" \
    || { echo "::error::cert.pem is not the leaf"; exit 1; }
openssl x509 -in "$LIVE/chain.pem" -noout -subject 2>/dev/null | grep -qi 'Mock Intermediate' \
    || { echo "::error::chain.pem is not the intermediate"; exit 1; }
echo "✓ cert.pem=leaf, chain.pem=intermediate"

echo "✓✓ certbot store layout verified"
