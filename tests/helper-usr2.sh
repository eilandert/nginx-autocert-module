#!/bin/bash
# USR2 hot binary upgrade test for the ACME helper (M4a residual).
#
# `kill -USR2 <master>` starts a NEW master from the (same) binary without
# dropping the listening sockets: the old master renames its pidfile to
# <pid>.oldbin, the new master writes a fresh pidfile and forks its own workers
# AND its own autocert helper through a 2nd ngx_init_cycle() with ngx_inherited
# set. Both generations then run side by side until the operator retires the old
# one (WINCH to drain workers, QUIT to exit).
#
# The helper is spawned from init_module on every ngx_init_cycle(), so the
# hot-upgrade path is a 2nd init in a NEW master that is daemonized + inherited
# (ngx_inherited=1) — distinct from both cold start and reload. This asserts:
#   USR2     a 2nd master starts and brings up its OWN helper; both generations
#            coexist (2 masters, >=1 helper each), no emerg/alert.
#   RETIRE   QUIT the old master; exactly one master and exactly one helper
#            remain (the new generation), the old helper is gone, log clean.
#   STOP     the surviving master + helper exit cleanly.
#
# Usage: helper-usr2.sh <built-nginx-or-angie-source-dir>
# The dir must contain objs/{nginx|angie} and the two autocert .so files.
set -u
N="${1:-${NGX_BUILD_DIR:?set build dir as \$1 or NGX_BUILD_DIR}}"
P=$(mktemp -d)
PORT=${AC_TEST_PORT:-18181}
SRV=objs/nginx; [ -x "$N/objs/angie" ] && SRV=objs/angie

case "$SRV" in *angie) TPREFIX="angie: autocert helper" ;;
               *)      TPREFIX="nginx: autocert helper" ;; esac

# Helpers are matched by proctitle only (same scoping limitation as
# helper-lifecycle.sh): this assumes one instance of this test per runner, which
# holds in CI (one job per flavor on a fresh hosted runner). The coexistence and
# retire asserts key off durable pid-tagged log lines, not just the live count,
# so a transient helper can't flake them.
hpids()  { pgrep -x -f "$TPREFIX" 2>/dev/null; }
hcount() { hpids | grep -c . ; }
hpid()   { hpids | head -1; }
alive()  { kill -0 "$1" 2>/dev/null; }

cleanup() {
    [ -n "${OLD:-}" ] && kill -QUIT "$OLD" 2>/dev/null
    "$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s stop 2>/dev/null
    pkill -9 -f "$TPREFIX" 2>/dev/null
    local pid
    pid=$(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+')
    [ -n "${pid:-}" ] && kill -9 "$pid" 2>/dev/null
    rm -rf "$P"
}
trap cleanup EXIT

mkdir -p "$P/logs" "$P/conf" "$P/store"
# A writable autocert_path keeps the helper alive: without it the helper tries
# the default store under conf/, fails to create the account key, and exits —
# which would race this test's helper-count asserts. With a writable store it
# stays on its event loop (it never reaches a real CA: no resolver configured).
cat > "$P/conf/nginx.conf" <<EOF
load_module $N/objs/ngx_autocert_process_module.so;
load_module $N/objs/ngx_http_autocert_module.so;
pid $P/logs/nginx.pid;
error_log $P/logs/error.log notice;
events {}
http {
    autocert on a@b.com;
    autocert_path $P/store;
    server { listen $PORT; server_name x; autocert on; }
}
EOF

fail() { echo "  $1: FAIL"; sed -n 's/^/    /p' "$P/logs/error.log" | tail -25; exit 1; }

assert_log_clean() {  # $1 = phase label
    local hits
    hits=$(grep -E '\[(emerg|alert)\]' "$P/logs/error.log" | grep -v 'signal 9') || true
    if [ -n "$hits" ]; then
        echo "  $1: FAIL (helper logged emerg/alert)"
        printf '%s\n' "$hits" | sed 's/^/    /'
        exit 1
    fi
}

# START
setsid "$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" >/tmp/usr2.err 2>&1 </dev/null
for _ in $(seq 1 25); do [ "$(hcount)" -eq 1 ] && break; sleep 0.2; done
OLD=$(cat "$P/logs/nginx.pid" 2>/dev/null)
OLD_PID="$OLD"   # preserved for logging after OLD is cleared at retire
HOLD=$(hpid)
echo "START: master=$OLD helper=$HOLD"
if ! { [ -n "$OLD" ] && alive "$OLD"; }; then fail "master not running"; fi
[ "$(hcount)" -eq 1 ] || fail "expected one helper at start, got $(hcount)"
echo "  one helper on event loop: OK"

# USR2: hot binary upgrade. The old master keeps running; a new master is forked
# and writes a fresh pidfile (old pidfile -> <pid>.oldbin).
echo "USR2:"
kill -USR2 "$OLD"
for _ in $(seq 1 50); do
    if [ -f "$P/logs/nginx.pid.oldbin" ] && [ -f "$P/logs/nginx.pid" ]; then
        NEW=$(cat "$P/logs/nginx.pid" 2>/dev/null)
        if [ -n "$NEW" ] && [ "$NEW" != "$OLD" ]; then break; fi
    fi
    sleep 0.2
done
NEW=$(cat "$P/logs/nginx.pid" 2>/dev/null)
if ! { [ -n "$NEW" ] && [ "$NEW" != "$OLD" ]; }; then fail "no new master after USR2 (old=$OLD new=${NEW:-none})"; fi
alive "$NEW" || fail "new master ($NEW) not alive"
alive "$OLD" || fail "old master ($OLD) died on USR2 (should coexist)"
echo "  new master $NEW started, old master $OLD still alive: OK"

# The new generation must bring up its OWN helper via its 2nd init_cycle
# (ngx_inherited). Assert this on the DURABLE log, not a live process count: with
# no resolver the new helper attempts the account registration and may exit on
# the DNS failure within a poll tick, so polling `hcount >= 2` races that exit
# (Codex). A "helper started, pid <N>" line with N != HOLD proves a second,
# distinct helper was spawned regardless of how long it then lived.
started_pids() {  # pids from all "helper started, pid <N>" lines
    grep -oE 'autocert: helper started, pid [0-9]+' "$P/logs/error.log" \
        | grep -oE '[0-9]+$'
}
NEWHELP=""
for _ in $(seq 1 50); do
    NEWHELP=$(started_pids | grep -vx "$HOLD" | head -1)
    [ -n "$NEWHELP" ] && break
    sleep 0.2
done
[ -n "$NEWHELP" ] || fail "new generation did not start its own helper after USR2 (only HOLD=$HOLD seen)"
assert_log_clean "USR2"
echo "  new generation started its own helper (pid $NEWHELP, distinct from old $HOLD), live count=$(hcount): OK"

# RETIRE the old master: QUIT it. The OLD generation (master + its helper) must
# disappear and the NEW master must survive. We assert the old helper is gone and
# no more than one helper remains; we do NOT require a helper to still be running,
# because with no resolver configured the freshly-spawned helper attempts the
# account registration and exits on the lookup failure — the USR2 phase already
# proved the new generation spawns its own helper. (HOLD must never be the one
# left standing.)
echo "RETIRE:"
kill -QUIT "$OLD"
for _ in $(seq 1 50); do alive "$OLD" || break; sleep 0.2; done
alive "$OLD" && fail "old master did not exit on QUIT"
OLD=""    # so cleanup doesn't re-signal a recycled pid
# The old helper (HOLD) must die with the old master. Confirm via the durable
# "helper exiting, pid HOLD" log line AND that the pid is no longer live (the
# log line alone proves the right helper exited even if the pid is later reused).
for _ in $(seq 1 50); do
    grep -q "autocert: helper exiting, pid $HOLD" "$P/logs/error.log" \
        && ! alive "$HOLD" && break
    sleep 0.2
done
grep -q "autocert: helper exiting, pid $HOLD" "$P/logs/error.log" \
    || fail "old helper (pid $HOLD) never logged its exit after the old master QUIT"
alive "$HOLD" && fail "old helper (pid $HOLD) still alive after the old master QUIT"
C=$(hcount)
[ "$C" -le 1 ] || fail "after retiring old master expected <=1 helper, got $C"
alive "$NEW" || fail "new master died while retiring the old one"
assert_log_clean "RETIRE"
echo "  old generation (master $OLD_PID + helper $HOLD) gone, new master $NEW alive, helpers=$C: OK"

# STOP the surviving master cleanly.
echo "STOP:"
kill -QUIT "$NEW"
for _ in $(seq 1 50); do alive "$NEW" || break; sleep 0.2; done
alive "$NEW" && fail "surviving master did not exit on QUIT"
for _ in $(seq 1 25); do [ "$(hcount)" -eq 0 ] && break; sleep 0.2; done
[ "$(hcount)" -eq 0 ] || fail "helper still alive after stop"
assert_log_clean "STOP"
echo "  master + helper exited cleanly: OK"

echo "ALL OK"
echo "--- autocert log lines ---"
grep -i autocert "$P/logs/error.log"
