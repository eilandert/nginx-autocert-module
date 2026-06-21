#!/usr/bin/env bash
#
# Per-CA account key path + legacy migration (M3, #15) — pure nginx, no CA.
#
# M3 moves the account key from the flat <store>/account.key to a per-CA
# <store>/accounts/<ca_hash>/account.key, and migrates an existing flat key into
# the new location ONCE at startup. The migration (mkdir + rename) runs in the
# driver BEFORE it contacts the CA, so an unreachable CA is fine — we only assert
# the move, not issuance.
#
# Inputs (env): SERVER_BIN (required), NGX_BUILD_DIR.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:?set SERVER_BIN to the built nginx/angie binary}"
NGX_BUILD_DIR="${NGX_BUILD_DIR:-$(cd "$(dirname "$SERVER_BIN")/.." && pwd)}"
HTTP_SO="$NGX_BUILD_DIR/objs/ngx_http_autocert_module.so"
[ -f "$HTTP_SO" ] || { echo "missing $HTTP_SO"; exit 1; }

PREFIX="${PREFIX:-/tmp/ac-acct-migrate}"

cleanup() {
    "$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf" -s stop 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$PREFIX"
mkdir -p "$PREFIX/logs" "$PREFIX/conf" "$PREFIX/store"

# Plant a legacy flat account key with recognizable content + 0600.
LEGACY_CONTENT="LEGACY-ACCOUNT-KEY-$$"
printf '%s\n' "$LEGACY_CONTENT" > "$PREFIX/store/account.key"
chmod 600 "$PREFIX/store/account.key"

cat > "$PREFIX/conf/nginx.conf" <<EOF
load_module $HTTP_SO;
error_log $PREFIX/logs/error.log notice;
# Keep worker 0 (the ACME driver) as root when this runs under the documented
# root command, so it can write the root-owned legacy store and perform the
# migration. nginx ignores this with a warning when the master is unprivileged
# (CI), where the store is already worker-owned — so it is correct either way.
user root;
events {}
http {
    autocert on admin@example.com;
    autocert_ca https://127.0.0.1:1/dir;     # unreachable: migration is pre-CA
    autocert_path $PREFIX/store;
    server {
        listen 8080;
        server_name a.example.com;
        autocert on;
    }
}
EOF

echo "== config accepted =="
"$SERVER_BIN" -t -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

echo "== start: driver migrates the legacy flat account key =="
"$SERVER_BIN" -p "$PREFIX" -c "$PREFIX/conf/nginx.conf"

ok=
for _ in $(seq 1 20); do
    if grep -q "autocert: migrated account key" "$PREFIX/logs/error.log"; then
        ok=1; break
    fi
    sleep 0.3
done
grep "account key" "$PREFIX/logs/error.log" | tail -3 || true
[ -n "$ok" ] || { echo "::error::migration notice not logged"; exit 1; }
echo "✓ migration notice logged"

# Flat key gone; new per-CA key present with the SAME content + 0600.
[ ! -e "$PREFIX/store/account.key" ] \
    || { echo "::error::flat account.key still present after migration"; exit 1; }

new_key=$(echo "$PREFIX"/store/accounts/*/account.key)
[ -s "$new_key" ] || { echo "::error::per-CA account key missing"; ls -R "$PREFIX/store"; exit 1; }

got=$(cat "$new_key")
[ "$got" = "$LEGACY_CONTENT" ] \
    || { echo "::error::migrated key content differs (got '$got')"; exit 1; }

perms=$(stat -c '%a' "$new_key")
[ "$perms" = "600" ] || { echo "::error::migrated key perms $perms, expected 600"; exit 1; }
echo "✓ legacy key moved to $new_key (content + 0600 preserved)"

dperms=$(stat -c '%a' "$(dirname "$new_key")")
[ "$dperms" = "700" ] || { echo "::error::per-CA dir perms $dperms, expected 700"; exit 1; }
echo "✓ per-CA account dir is 0700"

echo "ALL ACCOUNT-MIGRATION CHECKS PASSED"
