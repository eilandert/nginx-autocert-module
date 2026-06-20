#!/usr/bin/env bash
#
# Worker-0 ACME driver lifecycle test (P1 worker-0 migration; replaces the old
# helper-lifecycle.sh + helper-usr2.sh, which tested the removed helper process).
#
# The ACME engine runs on worker 0 behind an flock singleton lock
# (<autocert_path>/.driver.lock). This asserts:
#   START   exactly one worker arms the driver ("ACME driver armed on worker 0").
#   RELOAD  the lock hands off: the retiring worker 0 releases, a fresh worker 0
#           re-arms — so the armed-pid changes and is alive, and at most one
#           driver is live at a time. Clean error log (no emerg/alert).
#   CRASH   SIGKILL the driver's worker 0; the master respawns a worker that
#           re-arms the driver with a new pid.
#   STOP    master + workers exit cleanly, pidfile removed, no orphan worker.
#
# Usage: worker0-driver.sh   (env: NGX_BUILD_DIR, optional AC_TEST_PORT)
set -euo pipefail

N="${NGX_BUILD_DIR:?set NGX_BUILD_DIR to the built nginx/angie tree}"
SRV=nginx; [ -x "$N/objs/angie" ] && SRV=angie
HTTP_SO="$N/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PORT="${AC_TEST_PORT:-18185}"
P=/tmp/ac-worker0
STORE="$P/store"

cleanup() {
    "$N/objs/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s stop 2>/dev/null || true
    local pid
    pid=$(ss -ltnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+') || true
    if [ -n "${pid:-}" ]; then kill -9 "$pid" 2>/dev/null || true; fi
    rm -rf "$P"
}
trap cleanup EXIT

rm -rf "$P"; mkdir -p "$P/logs" "$P/conf" "$STORE"
cat > "$P/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
pid $P/logs/nginx.pid;
error_log $P/logs/error.log notice;
events {}
http {
    autocert on a@b.com;
    autocert_path $STORE;
    server { listen $PORT; server_name x.example.com; autocert on; }
}
EOF

LOG="$P/logs/error.log"
alive() { kill -0 "$1" 2>/dev/null; }
fail()  { echo "  $1: FAIL"; sed -n 's/^/    /p' "$LOG" 2>/dev/null | tail -25; exit 1; }

# The pid in the most recent "ACME driver armed on worker 0, pid <P>" line.
armed_pid()  { grep -oE 'ACME driver armed on worker 0, pid [0-9]+' "$LOG" 2>/dev/null \
                 | tail -1 | grep -oE '[0-9]+$'; }
armed_count() { grep -c 'ACME driver armed on worker 0' "$LOG" 2>/dev/null || true; }
acquired_count() { grep -c 'acquired driver lock' "$LOG" 2>/dev/null || true; }
released_count() { grep -c 'released driver lock' "$LOG" 2>/dev/null || true; }

# True iff $1 is a worker process whose parent is the master $2.
is_child_of() {  # $1 = pid, $2 = master pid
    local ppid
    ppid=$(ps -o ppid= -p "$1" 2>/dev/null | tr -d ' ') || return 1
    [ "$ppid" = "$2" ]
}

# No emerg/alert may appear (a SIGKILLed worker logs an expected 'signal 9'
# master line in the CRASH phase, exclude that).
assert_log_clean() {  # $1 = phase label
    local hits
    hits=$(grep -E '\[(emerg|alert)\]' "$LOG" | grep -v 'signal 9') || true
    if [ -n "$hits" ]; then
        echo "  $1: FAIL (emerg/alert logged)"; printf '%s\n' "$hits" | sed 's/^/    /'
        exit 1
    fi
}

# wait until armed_pid is set, is fresh, and points at a live worker child of MASTER
wait_armed() {  # $1 = "different from this pid" (optional)
    local prev="${1:-}" pid
    for _ in $(seq 1 100); do          # up to 20s — CI runners can be slow
        pid=$(armed_pid)
        if [ -n "$pid" ] && [ "$pid" != "$prev" ] && alive "$pid" \
           && is_child_of "$pid" "$MASTER"
        then
            echo "$pid"; return 0
        fi
        sleep 0.2
    done
    return 1
}

# ── START ──────────────────────────────────────────────────────────────────
setsid "$N/objs/$SRV" -p "$P" -c "$P/conf/nginx.conf" >/tmp/w0.err 2>&1 </dev/null
for _ in $(seq 1 50); do [ -s "$P/logs/nginx.pid" ] && break; sleep 0.2; done
MASTER=$(cat "$P/logs/nginx.pid" 2>/dev/null) || fail "no master pidfile"
A1=$(wait_armed) || fail "driver never armed on worker 0 (child of master $MASTER)"
[ "$(armed_count)" -eq 1 ] || fail "expected 1 armed line at start, got $(armed_count)"
[ "$(acquired_count)" -eq 1 ] || fail "expected 1 lock acquire at start, got $(acquired_count)"
[ -f "$STORE/.driver.lock" ] || fail "no .driver.lock in store dir"
echo "START: master=$MASTER, armed on worker 0 pid=$A1, lock acquired once: OK"

# ── RELOAD x2: lock hands off to a fresh worker 0 ───────────────────────────
PREV=$A1
for r in 1 2; do
    acq_before=$(acquired_count); rel_before=$(released_count)
    "$N/objs/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s reload 2>&1
    AN=$(wait_armed "$PREV") || fail "no fresh worker 0 re-armed after reload $r"
    # the old worker must release before/around the new acquire: both counts grew
    for _ in $(seq 1 50); do
        [ "$(acquired_count)" -gt "$acq_before" ] && [ "$(released_count)" -gt "$rel_before" ] && break
        sleep 0.2
    done
    [ "$(acquired_count)" -gt "$acq_before" ] || fail "reload $r: new worker 0 never acquired the lock"
    [ "$(released_count)" -gt "$rel_before" ] || fail "reload $r: old worker 0 never released the lock"
    # singleton snapshot: only one armed worker may be alive right now
    live=0
    while read -r pid; do
        if [ -n "$pid" ] && alive "$pid"; then live=$((live+1)); fi
    done < <(grep -oE 'armed on worker 0, pid [0-9]+' "$LOG" | grep -oE '[0-9]+$' | sort -u)
    [ "$live" -le 1 ] || fail "reload $r: $live drivers live at once (lock failed)"
    [ "$PREV" != "$AN" ] || fail "reload $r: worker 0 pid did not change"
    assert_log_clean "RELOAD $r"
    echo "RELOAD $r: lock handed off $PREV -> $AN (release+acquire logged), <=1 live, clean: OK"
    PREV=$AN
done

# ── CRASH: SIGKILL worker 0, the SAME master respawns + re-arms ──────────────
CRASHED=$PREV
kill -9 "$CRASHED" 2>/dev/null || fail "could not signal driver worker $CRASHED"
AN=$(wait_armed "$CRASHED") || fail "driver not re-armed after worker 0 crash (was $CRASHED)"
# the master that respawned it must be the SAME, still-alive master
alive "$MASTER" || fail "master $MASTER died on a worker crash (should respawn, not exit)"
[ "$(cat "$P/logs/nginx.pid" 2>/dev/null)" = "$MASTER" ] || fail "master pid changed after crash"
is_child_of "$AN" "$MASTER" || fail "re-armed worker $AN is not a child of master $MASTER"
grep -q "worker process $CRASHED exited on signal 9" "$LOG" \
    || fail "no 'worker $CRASHED exited on signal 9' line (crash not observed by master)"
echo "CRASH: worker 0 $CRASHED SIGKILLed -> master $MASTER respawned + re-armed as $AN: OK"

# ── STOP: clean teardown ────────────────────────────────────────────────────
"$N/objs/$SRV" -p "$P" -c "$P/conf/nginx.conf" -s stop 2>&1
for _ in $(seq 1 25); do [ -f "$P/logs/nginx.pid" ] || break; sleep 0.2; done
[ -f "$P/logs/nginx.pid" ] && fail "pidfile remains, master still alive"
echo "STOP: master exited (pidfile removed): OK"
# the last re-armed worker must be gone
for _ in $(seq 1 25); do alive "$AN" || break; sleep 0.2; done
alive "$AN" && fail "driver worker $AN still alive after stop"
echo "  driver worker gone: OK"

echo "✓ worker-0 ACME driver lifecycle (start/reload-handoff/crash-respawn/stop) verified"
