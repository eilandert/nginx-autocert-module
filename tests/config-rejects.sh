#!/usr/bin/env bash
#
# Config-time rejection tests (nginx -t only, no network/docker). Asserts the
# module fails configuration — rather than misbehaving at runtime — for invalid
# directive values.
#
# Cases:
#   - autocert_dns_hook_timeout 0;  (and negative) must be rejected: a
#     non-positive timeout otherwise reaches the driver as 0 and SIGKILLs every
#     dns-01 hook on the first poll tick, silently breaking all dns-01 issuance.
#
# Inputs (env):
#   SERVER_BIN   - path to the built nginx/angie binary (required)
#   NGX_BUILD_DIR- build dir holding objs/*.so (defaults to dir of SERVER_BIN)

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-cfgreject}"
rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Port 8443 avoids the privileged-bind failure that would make every `-t` fail
# regardless of the directive under test (the reason we grep for the SPECIFIC
# rejection message below, not just a non-zero exit).
PORT=8443

# Asserts `nginx -t` rejects the body AND logs the expected reason substring.
expect_reject() {
    local label="$1" body="$2" want="$3"
    cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on a@b.com;
    autocert_path $PREFIX/store;
$body
    server { listen $PORT; server_name x.example.com; }
}
EOF
    local out
    out=$("$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1 || true)
    if printf '%s' "$out" | grep -q "syntax is ok"; then
        echo "::error::$label: config was ACCEPTED but should be rejected"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if ! printf '%s' "$out" | grep -q "$want"; then
        echo "::error::$label: rejected, but not for the expected reason ($want)"
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "✓ $label rejected at config time"
}

# 0 is the value ngx_conf_set_sec_slot accepts but the driver cannot use; our
# explicit post-parse check rejects it with this message. (A negative value is
# already rejected by the sec parser itself, with a generic "invalid value".)
expect_reject "autocert_dns_hook_timeout 0" "    autocert_dns_hook_timeout 0;" \
    "autocert_dns_hook_timeout must be greater than 0"
expect_reject "autocert_dns_hook_timeout -1" "    autocert_dns_hook_timeout -1;" \
    "invalid value"

# Sanity: a positive timeout is accepted (config syntax ok).
cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log;
events {}
http {
    autocert on a@b.com;
    autocert_path $PREFIX/store;
    autocert_dns_hook_timeout 15s;
    server { listen $PORT; server_name x.example.com; }
}
EOF
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" 2>&1 | grep -q "syntax is ok" \
    || { echo "::error::a valid autocert_dns_hook_timeout was rejected"; exit 1; }
echo "✓ valid autocert_dns_hook_timeout accepted"

echo "✓✓ config-time rejection checks verified"
