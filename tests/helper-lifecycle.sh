#!/bin/bash
# Helper-process lifecycle test (M4a): the channel-managed ACME helper.
#
# Asserts:
#   START      master spawns exactly one helper, it runs the event loop.
#   RELOAD x2  after each reload exactly one helper lives (old generation is
#              QUIT over the channel and reaped, new one is JUST_RESPAWN). The
#              pid may change -- unlike the M1 stand-in, this helper is
#              respawned per reload like a worker. No leak, no orphan.
#   CRASH      kill the helper; the master respawns it automatically
#              (ngx_reap_children, respawn=1). No manual liveness check needed.
#   STOP       master + helper exit cleanly, pidfile removed, no SIGKILL.
#
# Usage: helper-lifecycle.sh <built-nginx-or-angie-source-dir>
# The dir must contain objs/{nginx|angie} and the two autocert .so files.
set -u
N="${1:-${NGX_BUILD_DIR:?set build dir as \$1 or NGX_BUILD_DIR}}"
P=$(mktemp -d)
PORT=${AC_TEST_PORT:-18177}
SRV=objs/nginx; [ -x "$N/objs/angie" ] && SRV=objs/angie

# nginx titles the helper "nginx: autocert helper"; Angie uses "angie: ...".
case "$SRV" in *angie) TPREFIX="angie: autocert helper" ;;
               *)      TPREFIX="nginx: autocert helper" ;; esac

# Scope helper matching to THIS test instance: the proctitle carries no prefix
# path, so match on the title and confirm the pid is a descendant of our master
# (cheap: our master pid changes per phase, so just match the title -- the trap
# cleans any straggler and we never run two instances of this script at once on
# the same port). Title match is exact (-x) to avoid the launcher/grep itself.
hpids()  { pgrep -x -f "$TPREFIX" 2>/dev/null; }
hcount() { hpids | grep -c . ; }
hpid()   { hpids | head -1; }

cleanup() {
    "$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s stop 2>/dev/null
    pkill -9 -f "$TPREFIX" 2>/dev/null
    # belt-and-braces: free the test port if anything orphaned
    local pid
    pid=$(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+')
    [ -n "${pid:-}" ] && kill -9 "$pid" 2>/dev/null
    rm -rf "$P"
}
trap cleanup EXIT

mkdir -p "$P/logs" "$P/conf"
writeconf() {  # $1 = extra top-level directives (e.g. "daemon off;")
    cat > "$P/conf/nginx.conf" <<EOF
load_module $N/objs/ngx_autocert_process_module.so;
load_module $N/objs/ngx_http_autocert_module.so;
pid $P/logs/nginx.pid;
error_log $P/logs/error.log notice;
${1:-}
events {}
http { autocert on a@b.com; server { listen $PORT; server_name x; autocert on; } }
EOF
}
writeconf
alive()  { kill -0 "$1" 2>/dev/null; }
fail()   { echo "  $1: FAIL"; sed -n 's/^/    /p' "$P/logs/error.log" | tail -20; exit 1; }

setsid "$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" >/tmp/s.err 2>&1 </dev/null
sleep 1
MPID=$(cat "$P/logs/nginx.pid" 2>/dev/null)
H1=$(hpid)
echo "START: master=$MPID helper=$H1"
if ! { [ -n "$H1" ] && alive "$H1"; }; then fail "helper not running"; fi
grep -q 'autocert: helper started' "$P/logs/error.log" || fail "no 'helper started' log"
[ "$(hcount)" -eq 1 ] || fail "expected one helper, got $(hcount)"
echo "  one helper on event loop: OK"

# Reload twice: exactly one helper survives each (old QUIT, new respawned).
for r in 1 2; do
    "$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s reload 2>&1; sleep 2
    C=$(hcount)
    [ "$C" -eq 1 ] || fail "after reload $r helper count=$C (leak/orphan)"
    echo "RELOAD $r: exactly one helper (pid $(hpid)): OK"
done

# Crash-respawn: kill the helper, master must bring a fresh one back.
HC=$(hpid)
kill -9 "$HC";
for _ in $(seq 1 25); do
    HN=$(hpid); [ -n "$HN" ] && [ "$HN" != "$HC" ] && break
    sleep 0.2
done
HN=$(hpid)
if ! { [ -n "$HN" ] && [ "$HN" != "$HC" ]; }; then fail "helper not respawned after crash (was $HC, now ${HN:-none})"; fi
[ "$(hcount)" -eq 1 ] || fail "after respawn helper count=$(hcount)"
echo "CRASH: respawned (pid $HC -> $HN): OK"

# Stop: clean teardown.
"$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s stop 2>&1
echo "STOP:"
for _ in $(seq 1 25); do [ -f "$P/logs/nginx.pid" ] || break; sleep 0.2; done
[ -f "$P/logs/nginx.pid" ] && fail "pidfile remains, master alive"
echo "  master exited (pidfile removed): OK"
for _ in $(seq 1 15); do [ "$(hcount)" -eq 0 ] && break; sleep 0.2; done
[ "$(hcount)" -eq 0 ] || fail "helper still alive after stop"
echo "  helper gone: OK"
# The final (shutdown) helper must have exited cleanly, not been SIGKILLed.
# (The CRASH phase deliberately SIGKILLs a helper; that 'signal 9' is expected
# and is excluded by checking only the last helper-exit line.)
LASTEXIT=$(grep 'autocert helper .* exited' "$P/logs/error.log" | tail -1)
case "$LASTEXIT" in
    *"exited with code 0"*) echo "  shutdown helper exited cleanly: OK" ;;
    *"signal 9"*) fail "shutdown helper SIGKILLed (ignored graceful signal): $LASTEXIT" ;;
    *) echo "  shutdown helper exit: $LASTEXIT" ;;
esac

# ---------------------------------------------------------------------------
# daemon off: no ngx_daemon() fork, so the cold helper is a real master child
# (channel-managed, not detached). Start in the background, verify one helper,
# then SIGQUIT the master and confirm both exit cleanly.
echo "DAEMON-OFF:"
writeconf "daemon off;"
"$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" >/tmp/s2.err 2>&1 &
DPID=$!
for _ in $(seq 1 25); do [ "$(hcount)" -eq 1 ] && break; sleep 0.2; done
[ "$(hcount)" -eq 1 ] || fail "daemon-off: expected one helper, got $(hcount)"
echo "  one helper (channel-managed, real child): OK"
kill -QUIT "$DPID"
for _ in $(seq 1 25); do alive "$DPID" || break; sleep 0.2; done
alive "$DPID" && fail "daemon-off: master did not exit on QUIT"
for _ in $(seq 1 15); do [ "$(hcount)" -eq 0 ] && break; sleep 0.2; done
[ "$(hcount)" -eq 0 ] || fail "daemon-off: helper still alive after master quit"
echo "  master + helper exited cleanly on QUIT: OK"
# restore default (daemon on) conf so cleanup's -s stop targets the right file
writeconf

# ---------------------------------------------------------------------------
# Cold-start crash (documented limitation): the very first, pre-daemon helper is
# spawned detached with respawn=0 (the orphaned process is not the real master's
# child, so the master can neither waitpid nor respawn it). Killing it before any
# reload therefore leaves NO helper until the next reload, which then spawns a
# fresh channel-managed one. This asserts that contract so a future regression
# (e.g. accidental respawn=1) is caught, and proves recovery via reload.
echo "COLD-CRASH:"
setsid "$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" >/tmp/s3.err 2>&1 </dev/null
for _ in $(seq 1 25); do [ "$(hcount)" -eq 1 ] && break; sleep 0.2; done
[ "$(hcount)" -eq 1 ] || fail "cold-crash: no cold helper to start with"
HX=$(hpid)
kill -9 "$HX"
# No respawn expected for the detached cold helper: count stays 0.
sleep 2
[ "$(hcount)" -eq 0 ] || fail "cold-crash: helper respawned unexpectedly (count=$(hcount))"
echo "  cold helper not auto-respawned (expected; respawn=0): OK"
# A reload recovers: spawns a fresh channel-managed helper.
"$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s reload 2>&1; sleep 2
[ "$(hcount)" -eq 1 ] || fail "cold-crash: reload did not recover helper (count=$(hcount))"
echo "  reload recovers a fresh helper: OK"
"$N/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s stop 2>&1
for _ in $(seq 1 25); do [ -f "$P/logs/nginx.pid" ] || break; sleep 0.2; done

echo "ALL OK"
echo "--- autocert log lines ---"
grep -i autocert "$P/logs/error.log"
