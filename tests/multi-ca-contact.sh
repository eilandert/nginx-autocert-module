#!/usr/bin/env bash
#
# Per-CA account contact test (issues.md MED "Per-CA accounts use one unrelated,
# first-vhost email").
#
# Two vhosts, each pinned (SRV-scope `autocert_ca`) to a DIFFERENT CA directory,
# each with its OWN `autocert on <email>`. The fix binds the account contact
# per-CA group, so each CA's newAccount must carry ITS vhost's mailto — not the
# first-vhost email shared across both CAs.
#
# Two mock ACME CAs (ports A/B) each log the `contact` array decoded from the
# JWS payload of their /acct (newAccount) POST. The full order then completes so
# we also prove the per-CA contact plumbing doesn't break issuance.
#
# Assertions:
#   1) CA-A's newAccount contact == "mailto:a-admin@example.com",
#   2) CA-B's newAccount contact == "mailto:b-admin@example.com",
#   3) both names issue + store a fullchain.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-multica-contact}"
CA_HOST="mockca.example.com"
CA_PORT_A=14041
CA_PORT_B=14042
DNS_NAME="ac-mcc-dns-$$"
DNS_PORT=15493
NAME_A="ca-a.example.com"
NAME_B="ca-b.example.com"
EMAIL_A="a-admin@example.com"
EMAIL_B="b-admin@example.com"

MOCK_PID=""
cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
    if [ -n "$MOCK_PID" ]; then kill "$MOCK_PID" 2>/dev/null || true; fi
    docker rm -f "$DNS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# One CA cert covering the shared CA host (both ports use the same SNI host).
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$PREFIX/ca-key.pem" -out "$PREFIX/ca.pem" -days 2 -nodes \
    -subj "/CN=$CA_HOST" -addext "subjectAltName=DNS:$CA_HOST" >/dev/null 2>&1

for n in "$NAME_A" "$NAME_B"; do
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$PREFIX/leaf-$n-key.pem" -out "$PREFIX/leaf-$n.pem" -days 2 \
        -nodes -subj "/CN=$n" -addext "subjectAltName=DNS:$n" >/dev/null 2>&1
done

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/${CA_HOST}/127.0.0.1 >/dev/null

# ---- mock ACME CAs (two ports, identical state machine) ---------------------
cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools, base64, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

HOST = "${CA_HOST}"
PORTS = {${CA_PORT_A}: "A", ${CA_PORT_B}: "B"}
LEAF = {
    "${NAME_A}": open("${PREFIX}/leaf-${NAME_A}.pem", "rb").read(),
    "${NAME_B}": open("${PREFIX}/leaf-${NAME_B}.pem", "rb").read(),
}
CONTACT_FILE = {"A": "${PREFIX}/contact-A", "B": "${PREFIX}/contact-B"}
nonces = ("nonce-%d" % i for i in itertools.count())

def b64url(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    @property
    def letter(self):
        return PORTS[self.server.server_address[1]]

    @property
    def base(self):
        return "https://%s:%d" % (HOST, self.server.server_address[1])

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
        b = self.base
        if self.path == "/dir":
            self._send(200, json.dumps({
                "newNonce": b + "/nonce",
                "newAccount": b + "/acct",
                "newOrder": b + "/order"}).encode())
        elif self.path == "/nonce":
            self._send(204)
        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

    do_HEAD = do_GET

    def do_POST(self):
        b = self.base
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n) if n else b""

        if self.path == "/nonce":
            self._send(204)

        elif self.path == "/acct":
            # Decode the JWS payload to capture the account contact, then record
            # it so the test can assert each CA got ITS vhost's mailto.
            try:
                jws = json.loads(raw.decode())
                payload = json.loads(b64url(jws["payload"]).decode())
                contact = payload.get("contact", [])
            except Exception:
                contact = []
            with open(CONTACT_FILE[self.letter], "w") as f:
                f.write(",".join(contact))
            self._send(201, b'{"status":"valid"}',
                       extra={"Location": b + "/acct/1"})

        elif self.path == "/order":
            self._send(201, json.dumps({
                "status": "pending",
                "finalize": b + "/finalize",
                "authorizations": [b + "/authz"],
            }).encode(), extra={"Location": b + "/order/1"})

        elif self.path == "/authz":
            if getattr(self.server, "chal_done", False):
                self._send(200, json.dumps({"status": "valid"}).encode())
            else:
                self._send(200, json.dumps({
                    "status": "pending",
                    "challenges": [{
                        "type": "http-01",
                        "status": "pending",
                        "token": "mock-token-%s" % self.letter,
                        "url": b + "/chal",
                    }],
                }).encode())

        elif self.path == "/chal":
            self.server.chal_done = True
            self._send(200, json.dumps({"status": "valid"}).encode())

        elif self.path == "/finalize":
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": b + "/cert",
            }).encode())

        elif self.path == "/order/1":
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": b + "/cert",
            }).encode())

        elif self.path == "/cert":
            name = "${NAME_A}" if self.letter == "A" else "${NAME_B}"
            self._send(200, LEAF[name],
                       ctype="application/pem-certificate-chain")

        else:
            self._send(404, b'{"type":"urn:ietf:params:acme:error:malformed"}')

def serve(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("${PREFIX}/ca.pem", "${PREFIX}/ca-key.pem")
    srv = HTTPServer(("0.0.0.0", port), H)
    srv.chal_done = False
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()

for p in PORTS:
    threading.Thread(target=serve, args=(p,), daemon=True).start()
threading.Event().wait()
PYEOF

echo "== starting mock ACME CAs on :$CA_PORT_A and :$CA_PORT_B =="
python3 "$PREFIX/mockca.py" &
MOCK_PID=$!
for port in $CA_PORT_A $CA_PORT_B; do
    for i in $(seq 1 30); do
        if curl -ksf --resolve ${CA_HOST}:${port}:127.0.0.1 \
            --cacert "$PREFIX/ca.pem" https://${CA_HOST}:${port}/dir >/dev/null 2>&1; then
            break
        fi
        sleep 0.5
        [ "$i" = 30 ] && { echo "::error::mock CA on :$port did not come up"; exit 1; }
    done
done

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/error.log notice;
events {}
http {
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_resolver_timeout 5s;
    autocert_path $PREFIX/store;

    # CA overrides do NOT inherit trust from http{} — repeat
    # autocert_ca_certificate inside each overriding server (index.md durable fact).
    server {
        listen 80;
        server_name ${NAME_A};
        autocert on ${EMAIL_A};
        autocert_ca https://${CA_HOST}:${CA_PORT_A}/dir;
        autocert_ca_certificate $PREFIX/ca.pem;
    }
    server {
        listen 80;
        server_name ${NAME_B};
        autocert on ${EMAIL_B};
        autocert_ca https://${CA_HOST}:${CA_PORT_B}/dir;
        autocert_ca_certificate $PREFIX/ca.pem;
    }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

echo "== waiting for both newAccount contacts =="
for i in $(seq 1 80); do
    [ -s "$PREFIX/contact-A" ] && [ -s "$PREFIX/contact-B" ] && break
    if grep -Eq 'autocert: (ACME order failed|account registration failed)' "$LOG"; then
        echo "::error::driver failed before both accounts registered"
        grep autocert "$LOG" | tail -30; exit 1
    fi
    sleep 0.5
    [ "$i" = 80 ] && { echo "::error::both newAccount contacts not captured"; grep autocert "$LOG" | tail -30; exit 1; }
done

GOT_A="$(cat "$PREFIX/contact-A")"
GOT_B="$(cat "$PREFIX/contact-B")"
echo "CA-A contact: $GOT_A"
echo "CA-B contact: $GOT_B"

[ "$GOT_A" = "mailto:${EMAIL_A}" ] \
    || { echo "::error::CA-A got \"$GOT_A\", want \"mailto:${EMAIL_A}\""; exit 1; }
[ "$GOT_B" = "mailto:${EMAIL_B}" ] \
    || { echo "::error::CA-B got \"$GOT_B\", want \"mailto:${EMAIL_B}\""; exit 1; }
echo "✓ each CA's newAccount carried its own vhost contact"

echo "== waiting for both certificates to issue =="
for n in "$NAME_A" "$NAME_B"; do
    for i in $(seq 1 80); do
        [ -f "$PREFIX/store/$n/fullchain.pem" ] && break
        sleep 0.5
        [ "$i" = 80 ] && { echo "::error::$n did not issue"; grep autocert "$LOG" | tail -30; exit 1; }
    done
done
echo "✓ both certificates issued and stored"

# ---- conflict reject: same CA, two different contacts -> EMERG at -t ---------
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
cat > "$PREFIX/conf/conflict.conf" <<EOF
load_module $HTTP_SO;
user root;
error_log $PREFIX/logs/conflict.log notice;
events {}
http {
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_path $PREFIX/store2;
    server {
        listen 80;
        server_name c1.example.com;
        autocert on one@example.com;
        autocert_ca https://${CA_HOST}:${CA_PORT_A}/dir;
        autocert_ca_certificate $PREFIX/ca.pem;
    }
    server {
        listen 80;
        server_name c2.example.com;
        autocert on two@example.com;
        autocert_ca https://${CA_HOST}:${CA_PORT_A}/dir;
        autocert_ca_certificate $PREFIX/ca.pem;
    }
}
EOF
echo "== config test: conflicting contacts for one CA must be rejected =="
if "$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/conflict.conf" 2>"$PREFIX/conflict-t.out"; then
    echo "::error::conflicting per-CA contacts were accepted"
    cat "$PREFIX/conflict-t.out"; exit 1
fi
grep -q "conflicting account contacts" "$PREFIX/conflict-t.out" \
    || { echo "::error::wrong rejection reason"; cat "$PREFIX/conflict-t.out"; exit 1; }
echo "✓ conflicting per-CA contacts rejected at config time"

echo "✓✓ per-CA account contact verified"
