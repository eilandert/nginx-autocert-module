#!/usr/bin/env bash
#
# Slow-drip / slowloris total-read-budget test (PR #37 follow-up).
#
# PR #37 bounded the TOTAL time the ACME HTTP client spends reading a response
# (r->read_deadline). Re-arming the per-IO timer on every NGX_AGAIN would let a
# peer that dribbles one byte just before each timeout hold the connection open
# up to the recv cap; the total-budget check cuts it off regardless.
#
# A live 60s budget is too slow for CI, so this test runs against a module
# built with -DNGX_AUTOCERT_READ_TOTAL=2000 (see the slowloris-read CI job) and
# stands up a mock "CA" that, on the very first response the helper reads (the
# directory GET), sends headers then dribbles the body one byte every ~700ms
# forever. Each byte resets the per-IO timer but the 2s total budget still
# fires, so the helper must abort with "exceeded the total time budget" within
# a few seconds (not minutes).
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required; must be built
#                  with -DNGX_AUTOCERT_READ_TOTAL=2000)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-slowloris}"
CA_HOST="mockca.example.com"
CA_PORT=14021
DNS_NAME="ac-slow-dns-$$"
DNS_PORT=15473
NAME="slow.example.com"
BUDGET_MS=2000

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

docker network ls >/dev/null
docker run -d --name "$DNS_NAME" \
    -p ${DNS_PORT}:53/udp -p ${DNS_PORT}:53/tcp \
    --entrypoint dnsmasq andyshinn/dnsmasq:2.83 \
    -k --address=/${CA_HOST}/127.0.0.1 >/dev/null

# ---- mock ACME server: dribbles the directory body forever ------------------
# Raw TLS socket so we control the byte cadence (BaseHTTPRequestHandler would
# buffer). We send a valid status + Content-Length far larger than we ever
# deliver, then emit one body byte every ~700ms. 700ms < the per-IO timeout so
# each byte keeps resetting it, but the 2s total budget still fires.
cat > "$PREFIX/mockca.py" <<PYEOF
import ssl, socket, time

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("${PREFIX}/ca.pem", "${PREFIX}/ca-key.pem")

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", ${CA_PORT}))
srv.listen(5)

while True:
    raw, _ = srv.accept()
    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except ssl.SSLError:
        raw.close()
        continue
    try:
        # Read (and ignore) the request line + headers.
        conn.settimeout(2)
        try:
            conn.recv(8192)
        except Exception:
            pass
        # Promise a long body, then dribble it one byte at a time, forever.
        hdr = (b"HTTP/1.1 200 OK\r\n"
               b"Content-Type: application/json\r\n"
               b"Content-Length: 100000\r\n"
               b"Replay-Nonce: drip-nonce\r\n\r\n")
        conn.sendall(hdr)
        conn.settimeout(None)
        while True:
            conn.sendall(b"{")
            time.sleep(0.7)
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
PYEOF

echo "== starting drip mock on :$CA_PORT =="
python3 "$PREFIX/mockca.py" &
MOCK_PID=$!
# We can't curl /dir (it never completes), so just wait for the port to listen.
for i in $(seq 1 30); do
    if (exec 3<>/dev/tcp/127.0.0.1/${CA_PORT}) 2>/dev/null; then
        exec 3>&- 3<&-; break
    fi
    sleep 0.5
    [ "$i" = 30 ] && { echo "::error::drip mock did not listen"; exit 1; }
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
    # High port: the helper aborts on the directory read before any challenge,
    # so :80 is never used — an unprivileged port keeps this job sudo-free.
    server { listen 18190; server_name ${NAME}; }
}
EOF

echo "== config test =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start =="
START=$(date +%s)
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

LOG="$PREFIX/logs/error.log"

# The total-read budget (2s) must fire even though each byte resets the per-IO
# timer. Allow generous wall slack for scheduling, but it must be FAR below a
# 60s default budget — a few seconds, proving the total cap (not per-IO) cut it.
echo "== waiting for the total-budget abort =="
aborted=
for i in $(seq 1 30); do
    if grep -q 'exceeded the total time budget' "$LOG"; then
        aborted=1; break
    fi
    if grep -q 'autocert: read from .* timed out' "$LOG"; then
        echo "::error::aborted on the per-IO timeout, not the total budget"
        grep autocert "$LOG" | tail -20; exit 1
    fi
    sleep 0.5
    [ "$i" = 30 ] && { echo "::error::no total-budget abort observed"; grep autocert "$LOG" | tail -20; exit 1; }
done

ELAPSED=$(( $(date +%s) - START ))
echo "✓ helper aborted on the total read budget after ~${ELAPSED}s"

# Must be FAR below a 60s default budget — a few seconds — proving the total cap
# (not the 30s per-IO timer the drip keeps resetting) is what cut it off.
if [ -z "$aborted" ] || [ "$ELAPSED" -gt 15 ]; then
    echo "::error::abort took ${ELAPSED}s (>15s); per-IO timer not capped by total budget"
    grep autocert "$LOG" | tail -20; exit 1
fi

echo "✓✓ slowloris total-read budget (${BUDGET_MS}ms) verified"
