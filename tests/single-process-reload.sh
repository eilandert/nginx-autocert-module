#!/usr/bin/env bash
#
# `master_process off` reload test (no network / no docker).
#
# In single-process mode the process survives a SIGHUP: nginx re-reads the config
# and re-runs every module's init_module, but NEVER calls exit_process /
# init_process again (ngx_single_process_cycle only calls init_cycle). Without an
# init_module reload hook the autocert driver keeps its per-CA engines, timers,
# in-flight order, and serve gate bound to the DEAD cycle and its freed pool — a
# reload then ignores added/removed issuance names and risks stale-cycle pointers.
#
# This module installs that hook (ngx_http_autocert_init_module -> driver_reload
# + serve_reload on the single-process path). We assert the observable contract:
#   1. the process SURVIVES the reload (no crash while tearing down the dead-cycle
#      engines/timers/order/cache and re-arming against the new cycle),
#   2. the driver logs that it re-armed against the NEW cycle,
#   3. the serve layer logs that it dropped its per-worker cache + name gate for
#      rebuild against the new config.
#
# Why no post-reload network probe: nginx core does not cleanly re-establish a
# listening socket after a single-process (`master_process off`) reload — both a
# `listen ssl` socket (wrong TLS version) and even a plain HTTP socket (HTTP/0.9
# garbage) come back broken. That is an upstream nginx limitation unrelated to
# this module (reproduces on the unpatched build), so process survival + the
# module's own reload log lines are the meaningful, module-controlled signals.
#
# Inputs (env):
#   SERVER_BIN    - built nginx/angie binary (required)
#   NGX_BUILD_DIR - dir holding objs/*.so (defaults to two levels up from BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"

HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-single-reload}"
PORT="${AC_TEST_PORT:-8463}"
A="a.example.com"
B="b.example.com"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store/$A" "$PREFIX/store/$B"

gen_cert() {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
        -keyout "$PREFIX/store/$1/privkey.pem" \
        -out    "$PREFIX/store/$1/fullchain.pem" \
        -days 2 -subj "/CN=$1" -addext "subjectAltName=DNS:$1" >/dev/null 2>&1
    chmod 600 "$PREFIX/store/$1/privkey.pem"
}

# A `listen ssl; autocert on;` server drives the serve gate + driver. $1 = the
# autocert server_name; it changes across the reload so the issuance name set
# changes, exercising driver_reload (new ca_list/names) + serve_reload (gate).
write_conf() {
    cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
master_process off;
daemon on;
pid $PREFIX/logs/nginx.pid;
events {}
http {
    autocert_path $PREFIX/store;
    server {
        listen $PORT ssl;
        server_name $1;
        autocert on;
    }
}
EOF
}

alive() {
    local pid
    pid="$(cat "$PREFIX/logs/nginx.pid" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

gen_cert "$A"
gen_cert "$B"
write_conf "$A"

echo "== config test (master_process off) =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
echo "✓ config accepted"

echo "== start single-process, autocert server_name=$A =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"
for _ in $(seq 1 30); do alive && break; sleep 0.2; done
if alive; then echo "✓ started"; else echo "::error::did not start"; exit 1; fi
start_pid="$(cat "$PREFIX/logs/nginx.pid")"

echo "== reload with a CHANGED issuance name set ($A -> $B) =="
write_conf "$B"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload
sleep 1.0

echo "== process survived the reload (same pid, still alive) =="
# Single-process reload reconfigures IN PLACE: the pid must be unchanged AND the
# process must still be alive — a crash in the dead-cycle teardown or the re-arm
# would either kill it or (if it somehow respawned) change the pid.
if alive && [ "$(cat "$PREFIX/logs/nginx.pid")" = "$start_pid" ]; then
    echo "✓ pid $start_pid survived the in-place reload"
else
    echo "::error::process did not survive the reload (crash in teardown/re-arm?)"
    tail -20 "$PREFIX/logs/error.log" | sed 's/^/    /'
    exit 1
fi

echo "== driver re-armed against the new cycle =="
if grep -q "autocert: reload (master_process off) — re-arming driver" \
        "$PREFIX/logs/error.log"; then
    echo "✓ driver re-armed against the new cycle on reload"
else
    echo "::error::driver did not log a single-process reload re-arm"
    grep -i autocert "$PREFIX/logs/error.log" | sed 's/^/    /' || true
    exit 1
fi

echo "== serve layer dropped its cache + name gate for rebuild =="
if grep -q "autocert: reload (master_process off) — dropping per-worker" \
        "$PREFIX/logs/error.log"; then
    echo "✓ serve cache + name gate dropped for rebuild"
else
    echo "::error::serve layer did not log a single-process reload gate drop"
    grep -i autocert "$PREFIX/logs/error.log" | sed 's/^/    /' || true
    exit 1
fi

echo "== a SECOND reload (back to $A) still survives =="
# Exercises the teardown path twice: the per-CA engines / in-flight cancel /
# cache drop from the first reload must leave clean state for the next one.
write_conf "$A"
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s reload
sleep 1.0
if alive && [ "$(cat "$PREFIX/logs/nginx.pid")" = "$start_pid" ]; then
    echo "✓ pid $start_pid survived a second reload"
else
    echo "::error::process did not survive the second reload"
    tail -20 "$PREFIX/logs/error.log" | sed 's/^/    /'
    exit 1
fi
n_rearm=$(grep -c "re-arming driver" "$PREFIX/logs/error.log" || true)
if [ "$n_rearm" -ge 2 ]; then
    echo "✓ driver re-armed on both reloads ($n_rearm)"
else
    echo "::error::expected >=2 driver re-arms, saw $n_rearm"; exit 1
fi

echo "✓ master_process off reload verified (driver re-armed, gate rebuilt, no crash)"
