#!/usr/bin/env bash
#
# Deterministic 400-on-challenge-respond -> re-poll -> finalize test (PR #35
# follow-up).
#
# PR #35 made ngx_autocert_order_respond_done treat a 400 on the challenge
# respond POST as recoverable: instead of aborting the order it WARNs and
# re-polls the authorization (RFC 8555 §7.5.1 — a reused, already-valid authz
# rejects a POST that tries to move its challenge to "ready"). Against live
# Pebble that 400 only happens on a non-deterministic reorder race, so this
# test stands up a tiny mock ACME CA (retry-after.sh pattern) that forces the
# exact path:
#
#   newOrder -> fetch authz (pending, one http-01 challenge)
#            -> POST challenge  => 400  (the recoverable case)
#            -> poll authz      => valid
#            -> finalize        => valid + certificate URL
#            -> download cert   => a canned PEM chain
#
# The helper never validates the leaf against its CSR key (it stores whatever
# the CA returns), so the mock can hand back a pre-baked self-signed chain.
#
# Assertions:
#   1) the helper logs the WARN "challenge respond got 400 ... re-polling",
#   2) the order still reaches "certificate issued and stored", proving the 400
#      did NOT abort the order (no "challenge respond failed").
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-400-repoll}"
CA_HOST="mockca.example.com"
CA_PORT=14011
DNS_NAME="ac-400-dns-$$"
DNS_PORT=15463
NAME="repoll.example.com"

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Self-signed cert for the mock CA (its own trust anchor); SAN must be the host
# the helper connects to so the verified-TLS hostname check passes.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

# A canned leaf cert + key for the order domain, handed back at download. The
# helper stores the chain verbatim (no CSR/key match check), so a fresh
# self-signed leaf is fine.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/leaf-key.pem" -out "$PREFIX/leaf.pem" -days 2 -nodes \
    -subj "/CN=$NAME" -addext "subjectAltName=DNS:$NAME" >/dev/null 2>&1

# dnsmasq maps the mock CA name to the host loopback (the mock listens on
# 0.0.0.0:$CA_PORT on the host).
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

# Drive the order through one deterministic 400 on the challenge respond.
state = {"respond_seen": False}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quiet
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
            d = {"newNonce": BASE + "/nonce",
                 "newAccount": BASE + "/acct",
                 "newOrder": BASE + "/order"}
            self._send(200, json.dumps(d).encode())
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
            # newOrder -> 201 Created, Location = order URL, finalize + authz.
            body = json.dumps({
                "status": "pending",
                "finalize": BASE + "/finalize",
                "authorizations": [BASE + "/authz"],
            }).encode()
            self._send(201, body, extra={"Location": BASE + "/order/1"})

        elif self.path == "/authz":
            # The helper POSTs the authz URL twice with an empty payload:
            # first the initial fetch (must be pending with an http-01
            # challenge), then the re-poll after the 400 (must be valid).
            if state["respond_seen"]:
                self._send(200, json.dumps({"status": "valid"}).encode())
            else:
                body = json.dumps({
                    "status": "pending",
                    "challenges": [{
                        "type": "http-01",
                        "status": "pending",
                        "token": "mock-token-abc123",
                        "url": BASE + "/chal",
                    }],
                }).encode()
                self._send(200, body)

        elif self.path == "/chal":
            # Challenge respond: the recoverable 400 (reused/valid authz).
            state["respond_seen"] = True
            self._send(400, b'{"type":"urn:ietf:params:acme:error:malformed",'
                            b'"detail":"authorization is not pending"}',
                       ctype="application/problem+json")

        elif self.path == "/finalize":
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": BASE + "/cert",
            }).encode())

        elif self.path == "/order/1":
            # order poll (if the helper polls the order after finalize).
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": BASE + "/cert",
            }).encode())

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
load_module $HTTP_SO;
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
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

# 1) The 400 must be logged as recoverable (WARN + re-polling), not as a fatal
#    "challenge respond failed".
echo "== waiting for the recoverable-400 WARN line =="
for i in $(seq 1 60); do
    if grep -q "challenge respond got 400 for \"${NAME}\"; re-polling" "$LOG"; then
        break
    fi
    if grep -q "challenge respond failed" "$LOG"; then
        echo "::error::400 aborted the order (challenge respond failed)"
        grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::no recoverable-400 WARN line"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ helper logged the recoverable 400 and re-polled the authorization"

# 2) The order must still finish: re-poll -> valid -> finalize -> download ->
#    store. The terminal success line proves the 400 was non-fatal.
echo "== waiting for issuance to complete =="
for i in $(seq 1 60); do
    if grep -q "certificate issued and stored for \"${NAME}\"" "$LOG"; then
        break
    fi
    if grep -Eq 'autocert: (challenge respond failed|finalize failed|order poll timed out|order did not become valid|certificate download failed|ACME order failed|authorization poll timed out)' "$LOG"; then
        echo "::error::order aborted after the 400"; grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::issuance did not complete after the 400"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ certificate issued and stored despite the 400 (re-poll -> finalize)"

[ -f "$PREFIX/store/${NAME}/fullchain.pem" ] \
    || { echo "::error::fullchain.pem not stored"; exit 1; }
echo "✓ fullchain.pem persisted"

echo "✓✓ 400-on-respond -> re-poll -> finalize verified deterministically"
