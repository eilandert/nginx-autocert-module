#!/usr/bin/env bash
#
# Deterministic finalize-before-ready recovery test.
#
# The CA flips the authorization to valid asynchronously, and the ORDER only
# transitions pending->ready a moment later (RFC 8555 §7.4). A finalize POSTed
# in that window is rejected with a 400 even though nothing is wrong — observed
# intermittently against Pebble (see issues.md "tls-alpn-issue M10c — finalize
# 400"). order.c now treats a finalize 400/403 as recoverable: poll the order
# until it reports "ready", then re-finalize once.
#
# This mock ACME CA forces the exact path deterministically:
#   newOrder -> authz (pending, http-01) -> challenge respond 200
#            -> authz poll => valid
#            -> finalize #1 => 400  (order not "ready" yet)
#            -> order poll  => "ready"
#            -> finalize #2 => 200  (order now "processing"/"valid")
#            -> order poll  => valid + certificate URL
#            -> download    => canned PEM chain
#
# Assertions:
#   1) the helper logs the recoverable-finalize WARN and re-finalizes,
#   2) the order still reaches "certificate issued and stored" (no
#      "finalize failed" abort).
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

PREFIX="${PREFIX:-/tmp/ac-fin-ready}"
CA_HOST="mockca.example.com"
CA_PORT=14031
DNS_NAME="ac-fin-dns-$$"
DNS_PORT=15483
NAME="finready.example.com"

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

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/leaf-key.pem" -out "$PREFIX/leaf.pem" -days 2 -nodes \
    -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/${CA_HOST}/127.0.0.1 >/dev/null

# ---- mock ACME server -------------------------------------------------------
cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = "https://${CA_HOST}:${CA_PORT}"
LEAF = open("${PREFIX}/leaf.pem", "rb").read()
nonces = ("nonce-%d" % i for i in itertools.count())

# State machine: count finalize attempts so the first is rejected (order not
# ready) and the second succeeds (order ready).
state = {"finalize_calls": 0}

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
            # First fetch: pending + http-01. After the challenge respond the
            # helper polls the authz -> valid.
            if state.get("chal_done"):
                self._send(200, json.dumps({"status": "valid"}).encode())
            else:
                self._send(200, json.dumps({
                    "status": "pending",
                    "challenges": [{
                        "type": "http-01",
                        "status": "pending",
                        "token": "mock-token-finready",
                        "url": BASE + "/chal",
                    }],
                }).encode())

        elif self.path == "/chal":
            state["chal_done"] = True
            self._send(200, json.dumps({"status": "valid"}).encode())

        elif self.path == "/finalize":
            state["finalize_calls"] += 1
            if state["finalize_calls"] == 1:
                # Too early: order not "ready" yet -> 400 (recoverable).
                self._send(400, b'{"type":"urn:ietf:params:acme:error:'
                                b'orderNotReady","detail":"order is not ready"}',
                           ctype="application/problem+json")
            else:
                # Second attempt accepted; order moves to valid.
                self._send(200, json.dumps({
                    "status": "valid",
                    "certificate": BASE + "/cert",
                }).encode())

        elif self.path == "/order/1":
            # Order poll. Until the 2nd finalize, report "ready" (the state the
            # recovered finalize is waiting for). After it, "valid" + cert.
            if state["finalize_calls"] >= 2:
                self._send(200, json.dumps({
                    "status": "valid",
                    "certificate": BASE + "/cert",
                }).encode())
            else:
                self._send(200, json.dumps({"status": "ready"}).encode())

        elif self.path == "/cert":
            self._send(200, LEAF, ctype="application/pem-certificate-chain")

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
    server { listen 80; server_name ${NAME}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

# 1) The finalize 400 must be logged as recoverable (poll-until-ready + retry),
#    not as a fatal "finalize failed".
echo "== waiting for the recoverable-finalize WARN line =="
for i in $(seq 1 60); do
    if grep -q "finalize got 400 for \"${NAME}\"; polling order" "$LOG"; then
        break
    fi
    if grep -q "finalize failed" "$LOG"; then
        echo "::error::finalize 400 aborted the order (finalize failed)"
        grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::no recoverable-finalize WARN line"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ helper logged the recoverable finalize 400 and polled the order"

# 2) The order must reach "ready" and the helper must re-finalize.
echo "== waiting for the re-finalize line =="
for i in $(seq 1 60); do
    if grep -q "order \"${NAME}\" now ready, re-finalizing" "$LOG"; then
        break
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::helper did not re-finalize after ready"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ helper re-finalized once the order was ready"

# 3) Issuance must complete.
echo "== waiting for issuance to complete =="
for i in $(seq 1 60); do
    if grep -q "certificate issued and stored for \"${NAME}\"" "$LOG"; then
        break
    fi
    if grep -Eq 'autocert: (finalize failed|order poll timed out|order did not become valid|certificate download failed|ACME order failed)' "$LOG"; then
        echo "::error::order aborted after the finalize 400"; grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::issuance did not complete"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ certificate issued and stored despite the early finalize 400"

[ -f "$PREFIX/store/${NAME}/fullchain.pem" ] \
    || { echo "::error::fullchain.pem not stored"; exit 1; }
echo "✓ fullchain.pem persisted"

echo "✓✓ finalize-before-ready recovery verified deterministically"
