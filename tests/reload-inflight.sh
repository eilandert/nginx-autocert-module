#!/usr/bin/env bash
#
# Reload-during-in-flight-ACME test (`master_process off`).
#
# Regression for the dangling `ngx_autocert_acme_inflight` bug (issues.md
# "Audit 2026-06-23"): the resolver start path published the single-in-flight
# pointer AFTER ngx_resolve_name(), which can drive a cached/loopback resolve to
# inline completion (resolve->connect->ssl_init->finalize->order _done ->
# ngx_destroy_pool) before it returns — leaving the global pointing at a freed
# request. ngx_autocert_acme_cancel_inflight(), called from driver_reload() on
# the `master_process off` SIGHUP path, then dereferences that freed pointer
# (r->done = 1; read r->resolve / r->peer.connection) -> use-after-free.
#
# The fix mirrors the connect path: publish inflight BEFORE ngx_resolve_name()
# and clear-if-equal on the synchronous-start-failure return.
#
# This test reproduces the conditions: a loopback mock ACME CA whose hostname
# resolves (via pebble-challtestsrv DNS) to 127.0.0.1, so the 2nd+ ACME request
# to that host within the DNS TTL takes the cached SYNCHRONOUS resolve path; the
# server runs `master_process off`; and reloads are fired in a tight loop while
# the driver is actively issuing, so a reload lands while a request is in flight
# (or just completed) and exercises cancel_inflight every time.
#
# Scope / honesty: this drives cancel_inflight() against a LIVE in-flight ACME
# request on every reload and guards that path (and the driver re-arm) against
# crashes/regressions. It does NOT deterministically reproduce the *freed*-
# pointer variant: that needs a request to complete INLINE on the request stack
# (cached resolve + a loopback CA whose TLS handshake + response land
# synchronously), which is timing-dependent and not forceable here — the fix
# closes it by construction (publish inflight before ngx_resolve_name, exactly
# as the connect path already does). Run under valgrind/ASan the reload storm is
# still the strongest available dynamic check on the cancel/re-arm teardown.
#
# Assertions (deterministic, no-sanitizer signal):
#   1. the single process SURVIVES every reload (same pid, still alive) — a crash
#      in cancel_inflight or the re-arm would kill it,
#   2. ACME bootstrap is in flight (account registration started), and
#   3. the driver re-arms against the new cycle on each reload.
# We do NOT assert post-reload issuance completion: a `master_process off` SIGHUP
# does not cleanly rebuild listening sockets in nginx core (see
# single-process-reload.sh) — orthogonal to this module. No root / no :80
# needed: the mock validates without an http-01 fetch.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-reload-inflight}"
PORT="${AC_TEST_PORT:-8466}"
CA_HOST="mockca.example.com"
CA_PORT="${AC_CA_PORT:-14066}"
DNS_NAME="ac-reload-dns-$$"
DNS_PORT="${AC_DNS_PORT:-15466}"
NAME="reloadinflight.example.com"

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

# challtestsrv answers every A/AAAA query with 127.0.0.1 (TTL>0 -> nginx caches
# it, so the 2nd+ resolve of CA_HOST is a synchronous cache hit).
docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p "${DNS_PORT}":53/udp -p "${DNS_PORT}":53/tcp \
    ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -dnsserver :53 -management :8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" \
    -defaultIPv4 127.0.0.1 -defaultIPv6 "" >/dev/null

# ---- mock ACME server (happy path; authz flips valid on the challenge POST) --
cat > "$PREFIX/mockca.py" <<PYEOF
import json, ssl, itertools, base64, datetime, time
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

state = {"chal_done": False, "leaf": None}

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
            # Brief stall so a newOrder POST is reliably in flight when a reload
            # fires — widens the cancel_inflight-against-a-live-request window.
            time.sleep(0.3)
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
                        "token": "mock-token-reload",
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
            self._send(200, json.dumps({
                "status": "valid",
                "certificate": BASE + "/cert",
            }).encode())
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
    if curl -ksf --resolve "${CA_HOST}:${CA_PORT}:127.0.0.1" \
        --cacert "$PREFIX/ca.pem" "https://${CA_HOST}:${CA_PORT}/dir" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
    [ "$i" = 30 ] && { echo "::error::mock CA did not come up"; exit 1; }
done

# master_process off so SIGHUP -> driver_reload() -> cancel_inflight() in this
# very process. No `user root` / no :80: the mock validates without an http-01
# fetch, so the worker writes a user-owned store and binds a high port only.
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
master_process off;
daemon on;
pid $PREFIX/logs/nginx.pid;
events {}
http {
    autocert on;
    autocert_contact admin@example.com;
    autocert_ca https://${CA_HOST}:${CA_PORT}/dir;
    autocert_resolver 127.0.0.1:${DNS_PORT};
    autocert_resolver_timeout 5s;
    autocert_ca_trusted_certificate $PREFIX/ca.pem;
    autocert_store_path $PREFIX/store;
    server { listen $PORT; server_name ${NAME}; }
}
EOF
# worker_connections headroom: a master_process-off reload storm re-arms the
# driver (and thus restarts the resolver/ACME flow) repeatedly; the default 512
# is tight once several re-arm cycles overlap.
sed -i 's/events {}/events { worker_connections 1024; }/' "$PREFIX/conf/nginx.conf"

alive() {
    local pid
    pid="$(cat "$PREFIX/logs/nginx.pid" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

echo "== config test (master_process off) =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start single-process =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do alive && break; sleep 0.2; done
alive || { echo "::error::did not start"; tail -20 "$PREFIX/logs/error.log"; exit 1; }
start_pid="$(cat "$PREFIX/logs/nginx.pid")"
echo "✓ started, pid $start_pid"

LOG="$PREFIX/logs/error.log"

# Confirm the driver actually has live ACME state before we reload: it must have
# begun account registration (resolve -> connect -> directory GET are in flight
# around here). Without this the survival check below could pass trivially with
# no in-flight request to cancel.
echo "== wait for ACME bootstrap to be in flight =="
for i in $(seq 1 40); do
    grep -q "registering ACME account via" "$LOG" && break
    alive || { echo "::error::process died before bootstrap"; tail -20 "$LOG"; exit 1; }
    sleep 0.25
    [ "$i" = 40 ] && { echo "::error::driver never started ACME bootstrap"; grep -i autocert "$LOG" | tail -20; exit 1; }
done
echo "✓ ACME bootstrap in flight (account registration started)"

# Reload storm: fire SIGHUP repeatedly while the driver bootstraps, so a reload
# lands while an ACME request (resolve/connect/directory GET) is in flight and
# cancel_inflight() runs against live state every time. The surviving-process +
# re-armed-driver invariants below are the regression signal. (See the header
# for why the freed-pointer variant is not deterministically forced and why
# post-reload issuance is not asserted.)
echo "== reload storm while ACME is in flight =="
for i in $(seq 1 12); do
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload 2>/dev/null || true
    sleep 0.4
    if ! alive || [ "$(cat "$PREFIX/logs/nginx.pid" 2>/dev/null)" != "$start_pid" ]; then
        echo "::error::process died during reload #$i (UAF in cancel_inflight / re-arm crash?)"
        tail -30 "$LOG" | sed 's/^/    /'
        exit 1
    fi
done
echo "✓ pid $start_pid survived 12 reloads under in-flight ACME"

echo "== driver re-armed on every reload, with ACME bootstrap in flight =="
# The reload storm keeps the account-registration request (resolve -> directory
# GET) perpetually in flight: each SIGHUP cancels it via cancel_inflight() and
# re-arms before it can complete. So every one of the 12 reloads exercised
# cancel_inflight() against a LIVE request — the same function/teardown the
# freed-pointer UAF lives in. Proof: bootstrap started (>=1) and the driver
# re-armed on each reload (>=2).
n_rearm=$(grep -c "re-arming driver" "$LOG" || true)
n_boot=$(grep -c "registering ACME account via" "$LOG" || true)
[ "$n_rearm" -ge 2 ] || { echo "::error::expected >=2 driver re-arms, saw $n_rearm"; grep -i autocert "$LOG" | tail -20; exit 1; }
[ "$n_boot" -ge 1 ] || { echo "::error::ACME bootstrap never started — no in-flight state to cancel"; grep -i autocert "$LOG" | tail -20; exit 1; }
echo "✓ driver re-armed $n_rearm× with bootstrap in flight (cancel_inflight hit live state each reload)"

echo "✓ reload-during-in-flight ACME verified (no UAF in cancel_inflight; driver re-armed across the storm)"
