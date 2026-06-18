#!/usr/bin/env bash
#
# HTTP 429 / Retry-After rate-limit awareness test (M9c).
#
# Pebble cannot be made to return 429, so this test stands up a tiny mock ACME
# server over TLS (Python) that:
#   - serves a directory (newNonce / newAccount / newOrder)
#   - answers newNonce with a fresh Replay-Nonce
#   - answers newAccount with 201 + Location (kid) so the helper registers
#   - answers EVERY newOrder with 429 + "Retry-After: 90" + a rateLimited
#     problem document (and a fresh Replay-Nonce so the next POST has one)
#
# The helper must then:
#   - log that it is honouring the Retry-After (parse + plumb proven), and
#   - hold the failing name for ~90s before the next order attempt — longer
#     than the 60s first-step exponential backoff, proving the CA's
#     Retry-After overrides our own guess (ngx_autocert_backoff_hold takes the
#     later of the two).
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

PREFIX="${PREFIX:-/tmp/ac-retryafter}"
CA_HOST="mockca.example.com"
CA_PORT=14001
DNS_NAME="ac-ra-dns-$$"
DNS_PORT=15453
NAME="rl.example.com"
RETRY_AFTER=90

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    [ -n "$MOCK_PID" ] && kill "$MOCK_PID" 2>/dev/null || true
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Self-signed cert for the mock CA (acts as its own trust anchor); SAN must be
# the host the helper connects to so the TLS hostname check passes.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

# dnsmasq so the helper's resolver maps the mock CA name to the host (the mock
# listens on 0.0.0.0:$CA_PORT on the host).
docker network ls >/dev/null
HOST_IP="127.0.0.1"
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/${CA_HOST}/${HOST_IP} >/dev/null

# ---- mock ACME server -------------------------------------------------------
cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, sys, itertools
from http.server import BaseHTTPRequestHandler, HTTPServer

BASE = "https://${CA_HOST}:${CA_PORT}"
RETRY_AFTER = ${RETRY_AFTER}
nonces = ("nonce-%d" % i for i in itertools.count())

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
            body = (b'{"type":"urn:ietf:params:acme:error:rateLimited",'
                    b'"detail":"too many orders"}')
            self._send(429, body, ctype="application/problem+json",
                       extra={"Retry-After": str(RETRY_AFTER)})
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

# renew_before 130s => sweep period = renew_before/2 = 65s, so the name becomes
# eligible again shortly after the 60s exponential step but BEFORE the 90s
# Retry-After — letting us prove the Retry-After hold wins.
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
    autocert_renew_before 130s;
    server { listen 80; server_name ${NAME}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

# 1) The Retry-After must be parsed and logged (parse + plumb proven).
echo "== waiting for the 429 / Retry-After log line =="
for i in $(seq 1 60); do
    if grep -q "rate limited (429) for \"${NAME}\", honouring Retry-After ${RETRY_AFTER} s" "$LOG"; then
        break
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::no Retry-After honour log line"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ helper logged honouring Retry-After ${RETRY_AFTER}s"

# 2) The failing name must be held ~90s (the Retry-After) before the next order
#    attempt, longer than the 60s exponential first step.
echo "== watching for two order attempts to measure the hold (up to ~150s) =="
deadline=$(( $(date +%s) + 160 ))
while :; do
    n=$(grep -c "starting ACME order for \"${NAME}\"" "$LOG" || true)
    [ "$n" -ge 2 ] && break
    [ "$(date +%s)" -ge "$deadline" ] && { echo "::error::did not observe 2 order attempts (got $n)"; grep autocert "$LOG" | tail -40; exit 1; }
    sleep 2
done

mapfile -t TS < <(grep "starting ACME order for \"${NAME}\"" "$LOG" \
    | sed -E 's#^([0-9]{4})/([0-9]{2})/([0-9]{2}) ([0-9:]{8}).*#\1-\2-\3 \4#' \
    | head -2)
t1=$(date -d "${TS[0]}" +%s)
t2=$(date -d "${TS[1]}" +%s)
gap=$(( t2 - t1 ))
echo "== order attempts at +0 and +${gap}s =="

if [ "$gap" -lt 85 ]; then
    echo "::error::name retried after ${gap}s (< 85s); Retry-After (${RETRY_AFTER}s) not honoured (would be 60s on plain backoff)"
    grep autocert "$LOG" | tail -40
    exit 1
fi
echo "✓ name held off ${gap}s (>= Retry-After ${RETRY_AFTER}s, beats 60s backoff)"

echo "✓✓ M9c 429 / Retry-After rate-limit awareness verified"
