#!/usr/bin/env bash
#
# ACME IPv4-literal directory test. Literal IPs must use IP-SAN validation,
# omit TLS SNI, and preserve the ordinary IPv4 Host authority with its port.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-ipv4-directory}"
CA_PORT=14444
HOST_FILE="$PREFIX/host"
SNI_FILE="$PREFIX/sni"
MOCK_PID=""

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then
        kill "$MOCK_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/conf" "$PREFIX/logs" "$PREFIX/store"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 \
    -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' >/dev/null 2>&1

cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = ${CA_PORT}
BASE = "https://127.0.0.1:%d" % PORT
HOST_FILE = "${HOST_FILE}"
SNI_FILE = "${SNI_FILE}"
nonces = ("nonce-%d" % i for i in itertools.count())

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass
    def _send(self, code, body=b"", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Replay-Nonce", next(nonces))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)
    def do_GET(self):
        if self.path == "/dir":
            with open(HOST_FILE, "w") as f:
                f.write(self.headers.get("Host", ""))
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
        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

def sni_cb(_sslobj, server_name, _ctx):
    with open(SNI_FILE, "w") as f:
        f.write("" if server_name is None else server_name)

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("${PREFIX}/ca.pem", "${PREFIX}/ca-key.pem")
ctx.set_servername_callback(sni_cb)
srv = HTTPServer(("127.0.0.1", PORT), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
PYEOF

python3 "$PREFIX/mockca.py" &
MOCK_PID=$!
sleep 0.2
kill -0 "$MOCK_PID" 2>/dev/null || { echo "::error::IPv4 mock did not start"; exit 1; }

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the root-created store under sudo
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://127.0.0.1:${CA_PORT}/dir;
    autocert_ca_certificate $PREFIX/ca.pem;
    autocert_path $PREFIX/store;
    server { listen 18090; server_name ipv4.example.com; }
}
EOF

"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

for i in $(seq 1 50); do
    [ -s "$HOST_FILE" ] && break
    if grep -q 'certificate name mismatch\|certificate verify failed' "$PREFIX/logs/error.log"; then
        echo "::error::IPv4 ACME TLS verification failed"
        grep autocert "$PREFIX/logs/error.log" | tail -20
        exit 1
    fi
    sleep 0.2
    [ "$i" = 50 ] && { echo "::error::IPv4 directory was not fetched"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }
done

[ "$(cat "$HOST_FILE")" = "127.0.0.1:${CA_PORT}" ] \
    || { echo "::error::wrong IPv4 Host header: $(cat "$HOST_FILE")"; exit 1; }
if [ ! -f "$SNI_FILE" ] || [ -s "$SNI_FILE" ]; then
    echo "::error::literal IPv4 sent SNI: $(cat "$SNI_FILE" 2>/dev/null || true)"
    exit 1
fi
grep -q 'ACME account registered' "$PREFIX/logs/error.log" \
    || { echo "::error::IPv4 directory did not progress through account registration"; grep autocert "$PREFIX/logs/error.log" | tail -20; exit 1; }

echo "✓ IPv4 IP-SAN verified, no SNI, Host: 127.0.0.1:${CA_PORT}"
