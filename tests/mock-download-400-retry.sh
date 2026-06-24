#!/usr/bin/env bash
#
# Deterministic 400-on-certificate-download -> re-poll order -> retry download
# test.
#
# ngx_autocert_order_download_done treats a transient non-200 on the certificate
# download (a POST-as-GET to the cert URL) as recoverable: instead of aborting a
# fully-issued order it WARNs, re-polls the order once (the order is already
# "valid", so poll_order_done routes valid->download), and retries the download
# with a fresh nonce. The real-world trigger is a second badNonce landing on the
# account layer's one-shot retry, which surfaces here as a terminal 4xx and used
# to throw the whole order away (seen as a Pebble "status 400" CI flake).
#
# Against live Pebble that double-badNonce is non-deterministic, so this test
# stands up a tiny mock ACME CA that forces the exact path:
#
#   newOrder -> fetch authz (pending, one http-01 challenge)
#            -> POST challenge  => 200  (valid)
#            -> poll authz      => valid
#            -> finalize        => valid + certificate URL
#            -> download cert    => 400  (the recoverable case, first hit)
#            -> poll order       => valid + certificate URL
#            -> download cert    => 200  (canned PEM chain, second hit)
#
# Assertions:
#   1) the helper logs the WARN "certificate download got status 400 ...
#      re-polling",
#   2) the order still reaches "certificate issued and stored", proving the 400
#      did NOT abort the order (no "certificate download failed").
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-dl-400-retry}"
CA_HOST="mockca.example.com"
CA_PORT=14013
DNS_NAME="ac-dl-400-dns-$$"
DNS_PORT=15465
NAME="dl400.example.com"

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

# challtestsrv maps the mock CA name to the host loopback (the mock listens on
# 0.0.0.0:$CA_PORT on the host).
docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null

# ---- mock ACME server -------------------------------------------------------
cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools, base64, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID

BASE = "https://${CA_HOST}:${CA_PORT}"
# The driver validates leaf<->order-key before storing, so sign the leaf over
# the CSR public key (like a real CA) instead of serving a static self-signed.
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

# challenge respond succeeds; the deterministic 400 is on the FIRST /cert GET.
state = {"chal_seen": False, "leaf": None, "cert_hits": 0}

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
        raw = self.rfile.read(n) if n else b""

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
            # First fetch: pending + http-01 challenge. After the challenge is
            # responded, report valid.
            if state["chal_seen"]:
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
            # Challenge respond succeeds; authz flips to valid on next poll.
            state["chal_seen"] = True
            self._send(200, json.dumps({
                "type": "http-01",
                "status": "valid",
                "url": BASE + "/chal",
            }).encode())

        elif self.path == "/finalize":
            payload = json.loads(raw.decode())["payload"]
            csr = b64url_dec(json.loads(b64url_dec(payload).decode())["csr"])
            state["leaf"] = make_leaf(csr)
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": BASE + "/cert",
            }).encode())

        elif self.path == "/order/1":
            # order poll: always valid + cert URL (re-poll after the download 400
            # routes valid->download again).
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": BASE + "/cert",
            }).encode())

        elif self.path == "/cert":
            # First download attempt: the recoverable 400. Second: the chain.
            state["cert_hits"] += 1
            if state["cert_hits"] == 1:
                self._send(400, b'{"type":"urn:ietf:params:acme:error:malformed",'
                                b'"detail":"order is not ready for download"}',
                           ctype="application/problem+json")
            else:
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
user root;   # worker-0 ACME driver writes the store; keep worker uid able to
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

# 1) The download 400 must be logged as recoverable (WARN + re-polling), not as a
#    fatal "certificate download failed".
echo "== waiting for the recoverable download-400 WARN line =="
for i in $(seq 1 60); do
    if grep -q "certificate download got status 400 for \"${NAME}\"; re-polling" "$LOG"; then
        break
    fi
    if grep -q "certificate download failed" "$LOG"; then
        echo "::error::download 400 aborted the order (certificate download failed)"
        grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::no recoverable download-400 WARN line"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ helper logged the recoverable download 400 and re-polled the order"

# 2) The order must still finish: re-poll -> valid -> download -> store. The
#    terminal success line proves the 400 was non-fatal.
echo "== waiting for issuance to complete =="
for i in $(seq 1 60); do
    if grep -q "certificate issued and stored for \"${NAME}\"" "$LOG"; then
        break
    fi
    if grep -Eq 'autocert: (finalize failed|order poll timed out|order did not become valid|certificate download failed|ACME order failed|authorization poll timed out)' "$LOG"; then
        echo "::error::order aborted after the download 400"; grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 60 ] && { echo "::error::issuance did not complete after the download 400"; grep autocert "$LOG" | tail -30; exit 1; }
done
echo "✓ certificate issued and stored despite the download 400 (re-poll -> retry)"

[ -f "$PREFIX/store/${NAME}/fullchain.pem" ] \
    || { echo "::error::fullchain.pem not stored"; exit 1; }
echo "✓ fullchain.pem persisted"

echo "✓✓ 400-on-download -> re-poll -> retry verified deterministically"
