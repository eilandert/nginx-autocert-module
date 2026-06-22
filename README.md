# nginx-autocert-module

[![Build & Test](https://github.com/eilandert/nginx-autocert-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/eilandert/nginx-autocert-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/codeql.yml)
[![Security Scanners](https://github.com/eilandert/nginx-autocert-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/eilandert/nginx-autocert-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/eilandert/nginx-autocert-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/valgrind.yml)

**Automatic TLS certificates for NGINX — built into the server.**

`nginx-autocert-module` is an [ACME](https://datatracker.ietf.org/doc/html/rfc8555)
client that lives *inside* NGINX. Add `autocert on;` to a vhost and NGINX itself
obtains, serves, and renews an ECDSA certificate from Let's Encrypt (or any ACME
CA) for that vhost's `server_name`s — no certbot, no cron job, no deploy hook, no
reload. The whole flow runs inside the worker, and the new certificate is served
on the very next TLS handshake. **Your existing `server_name` list *is* the domain
list.** Works on both NGINX and Angie (coexists with Angie's native `acme`).

> 📖 New here? Start with the walkthrough:
> **[Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/)**
> on deb.myguard.nl.

---

## Quick start — set and forget

**One directive.** Add `autocert on;` to a vhost, make sure NGINX can reach the CA
(a `resolver`), and you are done — issuance and renewal then happen on their own,
forever.

```nginx
load_module modules/ngx_http_autocert_module.so;

http {
    resolver 1.1.1.1;                  # so NGINX can reach the ACME CA

    server {
        listen 80;                     # CA validates here over HTTP-01
        listen 443 ssl;
        server_name example.com www.example.com;

        autocert on;                   # ← the whole feature. Nothing else needed.
        # no ssl_certificate / ssl_certificate_key — autocert supplies them
    }
}
```

That is a complete, production-ready config. The first handshake triggers issuance
from Let's Encrypt; a self-signed placeholder is served for the few seconds until
the real certificate lands, after which the module renews it on its own (by default
7 days before expiry). Add a vhost, set `autocert on;`, reload once — that's the
whole workflow.

Everything below is for when you want *more* — LE staging, wildcards, DNS-01, a
different CA, EAB. **None of it is needed for the common case above.**

---

## Why

- **No moving parts.** Issuance, renewal, and serving all happen inside the
  running server. Nothing to install alongside, nothing to schedule.
- **Three challenge types:** `http-01` (default), `tls-alpn-01`
  ([RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737)), and `dns-01`.
- **Wildcards** via `dns-01` and an operator-supplied DNS hook (the only challenge
  type the ACME spec allows for `*.example.com`).
- **External Account Binding (EAB)** for commercial CAs (ZeroSSL, Sectigo, Google)
  that gate `newAccount` behind a key-id + HMAC key.
- **Certbot-compatible store** option — drop-in `live/<domain>/` layout — alongside
  the module's own hardened default.
- **Multiple CAs per instance**, selected per-vhost; each CA gets its own account
  and account key.
- **Per-SNI serving** — the right certificate is chosen in the TLS handshake from
  the requested SNI, with a self-signed bootstrap cert served until issuance lands.

---

## Full syntax — one annotated config

Every production directive below, with realistic values. Each line carries a
`# context | default: …` comment. `http{}`-only directives live in `http{}`;
the rest may also appear per-`server{}`.

```nginx
http {
    resolver 127.0.0.1 [::1] valid=300s;        # core nginx; autocert falls back to this if autocert_resolver is unset

    # ---- instance-wide defaults (folded into every server) ----
    autocert            on;                      # http,server | default: off
    autocert_contact    admin@example.com;       # http,server | ACME account email (optional)
    autocert_ca         https://acme-v02.api.letsencrypt.org/directory;
                                                 # http,server | default: LE production (mutually exclusive with autocert_staging)
    autocert_staging    off;                     # http,server | default: off          (on = LE staging directory)
    autocert_store_path       /var/lib/autocert;       # http only   | default: autocert     (relative → resolved against nginx prefix)
    autocert_store_layout      default;                 # http only   | default: default       (default | certbot)
    autocert_key_type   p384;                     # http only   | default: p384          (p384 | p256; OpenSSL secp384r1/secp256r1 also accepted)
    autocert_challenge  http-01;                  # http only   | default: http-01      (http-01 | tls-alpn-01 | dns-01)
    autocert_renew_before 7d;                     # http only   | default: 7d           (renew this long before notAfter)

    # ---- resolver used to REACH the CA (not for dns-01 validation) ----
    autocert_resolver         127.0.0.1 [::1];    # http only   | default: falls back to core `resolver` above
    autocert_resolver_timeout 30s;                # http only   | default: 30s

    # =====================================================================
    # 1) Plain HTTP-01 vhost. Needs `listen 80;`. CA fetches the token
    #    over plain HTTP from /.well-known/acme-challenge/<token>.
    # =====================================================================
    server {
        listen 80;
        listen 443 ssl;
        server_name www.example.com example.com;
        autocert on;                              # http,server | default: off  (server-level `autocert on` is what seeds the empty cert arrays)
        # no ssl_certificate / ssl_certificate_key — autocert supplies them
    }

    # =====================================================================
    # 2) DNS-01 wildcard vhost. Requires dns-01 + both hooks (below).
    #    Wildcards are ONLY issuable under dns-01. Two ways to ask for one:
    #
    #    (a) put the wildcard directly in server_name (this vhost then also
    #        ROUTES every subdomain — fine for a single catch-all vhost):
    server {
        listen 443 ssl;
        server_name example.org *.example.org;
        autocert on;                              # http,server | default: off
    }
    #    (b) keep concrete per-subdomain vhosts and SHARE one wildcard cert via
    #        autocert_wildcard — no wildcard in server_name, no catch-all, and
    #        the covered concrete names are NOT issued separately:
    server {
        listen 443 ssl;
        server_name a.example.net;
        autocert on;
        autocert_wildcard *.example.net;          # http,server | served from the wildcard
    }
    server {
        listen 443 ssl;
        server_name b.example.net;
        autocert on;
        autocert_wildcard *.example.net;          # same cert; declared once in http{} also works
    }

    # =====================================================================
    # 3) A second CA with EAB (e.g. ZeroSSL). This vhost OWNS its CA
    #    selector, so it inherits NO trust bundle / EAB from http{} —
    #    everything CA-bound must be set here explicitly.
    # =====================================================================
    server {
        listen 80;
        listen 443 ssl;
        server_name shop.example.com;
        autocert on;                              # http,server | default: off
        autocert_contact billing@example.com;     # this CA's account email
        autocert_ca https://acme.zerossl.com/v2/DV90;
                                                  # http,server | default: LE production
        autocert_eab_kid       AbCdEf0123456789;  # http,server | default: (none)  (both EAB lines or neither)
        autocert_eab_hmac_key  bX9...base64url...; # http,server | default: (none)
        # autocert_ca_trusted_certificate /etc/ssl/internal-ca.pem;  # http,server | default: (none)  — only for a private CA
    }

    # =====================================================================
    # 4) DNS-01 hooks — http{}-global, mandatory when challenge is dns-01.
    #    Absolute paths only. argv = {hook, _acme-challenge.<domain>, <txt>}.
    # =====================================================================
    autocert_challenge             dns-01;        # http only   | default: http-01
    autocert_dns_hook_add          /etc/nginx/acme/dns-add.sh;    # http only | default: (none)  (absolute path)
    autocert_dns_hook_remove       /etc/nginx/acme/dns-del.sh;    # http only | default: (none)  (absolute path)
    autocert_dns_propagation_delay 10s;           # http only   | default: 10s  (wait after add-hook before asking CA to validate)
    autocert_dns_hook_timeout      30s;           # http only   | default: 30s  (per-hook exec timeout; must be > 0)
}
```

> The four `autocert_dns_*` lines and the wildcard server only make sense together —
> the snippet shows them in one block for reference. A real config picks one
> challenge type via the single `autocert_challenge` directive.

---

## Directive reference

`http` = `http{}` (main) context; `server` = `server{}`. `http,server` directives
set an instance-wide default in `http{}` that each `server{}` may override.

| Directive | Context | Default | Description |
|---|---|---|---|
| `autocert on\|off` | http, server | `off` | Master switch. A `server{}`-level `autocert on` is what seeds the empty cert arrays so a cert-less vhost still builds an SSL_CTX. |
| `autocert_contact <email>` | http, server | (none) | ACME account contact email (one `@`, non-empty both sides). Picked per CA group — the first non-empty contact from a vhost in that group. (Was the optional 2nd arg of `autocert on`.) |
| `autocert_wildcard *.rest [*.rest …]` | http, server | (none) | Declare wildcard SAN(s) for this scope **without** putting `*.` in `server_name` (which would also make the vhost a subdomain catch-all). In `http{}` it applies to every enabled vhost; a `server{}` occurrence adds to that vhost. **dns-01 only.** A concrete `server_name` the wildcard covers (one leading label, e.g. `a.example.com` under `*.example.com`) is served from the wildcard cert, not issued separately. Repeatable; sole-leading-label form only. |
| `autocert_ca <url>` | http, server | LE production `https://acme-v02.api.letsencrypt.org/directory` | ACME directory URL to issue against. Distinct effective URLs become distinct CA groups. Mutually exclusive with `autocert_staging`. |
| `autocert_staging on\|off` | http, server | `off` | Shorthand for the LE staging directory (`https://acme-staging-v02.api.letsencrypt.org/directory`). For CI; no production rate limits. Mutually exclusive with `autocert_ca`. |
| `autocert_ca_trusted_certificate <file>` | http, server | (none) | PEM trust bundle verifying a private CA's TLS endpoint. CA-bound: a server that overrides the CA does **not** inherit it. Made absolute against the nginx prefix. |
| `autocert_eab_kid <key-id>` | http, server | (none) | EAB key identifier ([RFC 8555 §7.3.4](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4)) for CAs requiring External Account Binding. Both-or-neither with `autocert_eab_hmac_key`. CA-bound. |
| `autocert_eab_hmac_key <b64url>` | http, server | (none) | EAB HMAC key (base64url). Paired with `autocert_eab_kid`. CA-bound. |
| `autocert_store_path <path>` | http | `autocert` (→ `<prefix>/autocert`) | Root of the cert / account-key store. Relative paths resolve against the nginx prefix, not the CWD. |
| `autocert_store_layout default\|certbot` | http | `default` | On-disk layout: the module's own hardened layout, or a certbot-compatible `live/` layout. (`secure` accepted as an alias for `default`.) |
| `autocert_key_type p384\|p256` | http | `p384` | ECDSA curve for issued certs (and the account key). The OpenSSL names `secp384r1`/`secp256r1` (and `ecdsa-p384`/`ecdsa-p256`) are also accepted. |
| `autocert_challenge http-01\|tls-alpn-01\|dns-01` | http | `http-01` | ACME challenge type. `dns-01` is required for wildcards and requires both DNS hooks. |
| `autocert_renew_before <time>` | http | `7d` | Renew this long before a cert's `notAfter`. |
| `autocert_resolver <addr> [addr…]` | http | falls back to core `resolver` | DNS resolver(s) used to reach the CA host. Same `address[:port] valid= ipv6=` syntax as core `resolver`. |
| `autocert_resolver_timeout <time>` | http | `30s` | Timeout for that DNS resolution. |
| `autocert_dns_hook_add <path>` | http | (none) | Absolute path to the executable that **publishes** the dns-01 TXT record. Required when challenge is `dns-01`. |
| `autocert_dns_hook_remove <path>` | http | (none) | Absolute path to the executable that **removes** the TXT record after validation. Required when challenge is `dns-01`. |
| `autocert_dns_propagation_delay <time>` | http | `10s` | Wait after the add-hook returns before asking the CA to validate. `0` = no wait. |
| `autocert_dns_hook_timeout <time>` | http | `30s` | Per-hook exec timeout before SIGKILL. Must be `> 0`. |

**Config-time rejections to know about:**

- `autocert_ca` + `autocert_staging` on the same CA → emerg (mutually exclusive).
- `dns-01` selected but a hook missing → emerg (`requires both …`).
- `autocert_eab_kid` / `autocert_eab_hmac_key` — one set without the other → emerg.
- `autocert_wildcard` with a non `*.`-form argument → emerg (sole-leading-label only).
- `autocert_wildcard` under a non-dns-01 challenge → emerg (a wildcard is unissuable over http-01/tls-alpn-01).
- Two vhosts naming the **same CA URL** with different trust bundle / EAB / account
  email → emerg (one CA URL = one trust bundle, one EAB, one account).
- One `server_name` claimed by two vhosts pinned to different CAs → emerg
  (one name = one cert from one CA).

---

## Challenges

Pick one with `autocert_challenge` (it is `http{}`-global — one type per instance).
The module asks the CA only for the configured type and fails the order if the CA
offers no matching challenge.

| Type | What it needs | Wildcards |
|---|---|---|
| `http-01` (default) | A `listen 80;` vhost. The CA fetches the token over **plain HTTP** at `/.well-known/acme-challenge/<token>`. | No |
| `tls-alpn-01` | A `listen 443 ssl;` vhost. Validation is a TLS handshake with ALPN `acme-tls/1` + SNI. The module serves a challenge cert in-handshake. | No |
| `dns-01` | Both DNS hooks (below). No `:80`/`:443` needed for validation itself. | **Yes** — the only type that can issue `*.example.com`. |

The HTTP-01 handler is registered once in the content phase for the whole
`http{}` block, matches the `/.well-known/acme-challenge/` URI prefix, and serves
the token only when the resolved server has autocert enabled. The `:80` vhost that
answers the CA must therefore be (or inherit) an autocert-enabled server — a bare
`listen 80;` vhost with autocert disabled will decline the challenge. The `:80` /
`:443` requirements above are the ACME protocol's, not enforced by the module.

### DNS-01 hook contract

When `autocert_challenge dns-01` is active you must supply **both**
`autocert_dns_hook_add` and `autocert_dns_hook_remove`, each an **absolute path**.
The module runs them with **`fork` + `execve`** — no shell, no `system()`. Both
hooks receive the **same positional argv**:

```
argv[0] = <hook path>                 # the configured absolute path
argv[1] = "_acme-challenge.<domain>"  # record name; a leading "*." is stripped
argv[2] = "<txt-value>"               # 43-char base64url(SHA-256(keyauth))
argv[3] = NULL
```

**No environment variables are added by the module** — the hook inherits the
worker's environment verbatim. This is the certbot-manual convention: pass your
DNS-provider credentials in the worker's environment; the domain and value arrive
as `argv[1]` / `argv[2]`, *not* as `CERTBOT_DOMAIN` / `CERTBOT_VALIDATION`.

Flow and timing:

1. Add-hook runs, publishing the TXT record. Must exit `0`; a non-zero exit or a
   signal fails the order.
2. The module waits `autocert_dns_propagation_delay` (default `10s`) for DNS to
   propagate, then asks the CA to validate.
3. After validation the remove-hook runs (same argv). A remove failure is
   non-fatal — the record expires by TTL.

Each hook exec is bounded by `autocert_dns_hook_timeout` (default `30s`, must be
`> 0`); on timeout the whole hook process group is SIGKILLed. The hook runs on
worker 0 and blocks it for up to the timeout (only one order runs at a time).

For a wildcard `*.example.org` the ACME identifier is `*.example.org`, but the
hook is called with the base — `argv[1] = "_acme-challenge.example.org"`.

A tiny add-hook (RFC 2136 `nsupdate` flavour):

```sh
#!/bin/sh
# argv: $1 = _acme-challenge.<domain>   $2 = <txt-value>
nsupdate -k /etc/nginx/acme/tsig.key <<EOF
server 192.0.2.53
update add $1 60 IN TXT "$2"
send
EOF
```

The matching remove-hook is identical with `update delete $1 IN TXT "$2"`.

---

## Store layout

The store root is `autocert_store_path` (default `autocert`, resolved against the nginx
prefix). On disk a domain maps to a segment: literal names use themselves; a
wildcard `*.rest` is stored under `_wildcard_.rest`. Certificates are committed
atomically via `renameat2` on Linux ≥ 3.15; on a filesystem lacking
`RENAME_EXCHANGE` / `RENAME_NOREPLACE` the commit is deferred (the existing cert is
kept and renewal retries) rather than risking a mismatched pair, so a half-written
pair is never served. For a wildcard the cache entry, store dir, and the
≤1 stat/sec throttle are keyed by the shared `_wildcard_.<rest>` segment — one
entry for all subdomains, not per concrete SNI.

**`default`** — files live directly under `<path>` (the module's own hardened layout):

| Path | Mode |
|---|---|
| `<path>/<domain>/` | `0700` |
| `<path>/<domain>/privkey.pem` | `0600` |
| `<path>/<domain>/fullchain.pem` | `0644` |

**`certbot`** — certbot-compatible `live/` tree:

| Path | Mode |
|---|---|
| `<path>/live/` | `0755` |
| `<path>/live/<domain>/` | `0700` |
| `<path>/live/<domain>/privkey.pem` | `0600` |
| `<path>/live/<domain>/fullchain.pem` | `0644` |
| `<path>/live/<domain>/cert.pem` | `0644` (leaf only) |
| `<path>/live/<domain>/chain.pem` | `0644` (intermediates; may be empty) |

`cert.pem` / `chain.pem` exist for certbot-tool compatibility; the serve path only
reads `fullchain.pem` + `privkey.pem`.

**Account keys** (per CA, both layouts):

```
<path>/accounts/<ca_hash>/account.key      # 0600, unencrypted PKCS#8 PEM
<path>/accounts/                            # 0700
<path>/accounts/<ca_hash>/                  # 0700
```

`<ca_hash>` is the leading 64 bits of `SHA-256(<canonical CA URL>)` as 16 lowercase
hex chars. Staging and production are different URLs → different hashes → fully
isolated accounts. The account key is rejected on load unless it is a regular file,
owned by the worker's euid, with no group/other permission bits.

**Permissions — the store must be writable by the worker user.** Worker 0 creates
and writes everything under `autocert_store_path`, so that tree must be owned by the
nginx worker user:

```sh
chown -R www-data /var/lib/autocert
chmod 0700 /var/lib/autocert
```

If a previous run created the store as root, fix it once with
`chown -R <worker-user> <autocert_store_path>`. Worker 0 also holds a singleton lock at
`<path>/.driver.lock` (`0600`).

---

## How it works

1. **One driver, worker 0.** The ACME engine — account bootstrap, order flow,
   renewal scheduler — runs in exactly one process: worker 0 (or the single
   process under `master_process off`). It is a deterministic, zero-IPC election:
   a `flock` on `<path>/.driver.lock` guarantees a single driver even across a
   reload generation. Every other worker only serves challenges and certificates.

2. **Per-SNI serving.** On each TLS handshake a cert callback resolves the SNI,
   checks it against the set of issuable names, and serves the matching cert from a
   per-worker cache (reloaded by mtime, throttled to ≤1 stat/sec/name). A name with
   no issued cert yet gets a self-signed **bootstrap** cert (CN `localhost`) — the
   honest pre-issuance state; the client sees a name mismatch until the real cert
   lands. (Under `acme-tls/1` the callback fails closed instead of leaking the
   bootstrap cert.)

3. **Renewal.** A periodic sweep on worker 0 checks each name's stored
   `fullchain.pem`. A name is due — and gets reissued — when no cert is stored, the
   cert is unreadable, or `now >= notAfter − autocert_renew_before` (default `7d`).
   The sweep runs at most every 12 h and at least every 60 s; failures back off
   exponentially (60 s base, capped at 1 h), and a CA `429 Retry-After` is honoured.

4. **Staging vs production.** The default CA is Let's Encrypt **production**. Set
   `autocert_staging on;` to exercise the full issuance flow against LE **staging**
   without burning production rate limits — useful in CI. Staging certs are not
   publicly trusted, and (per the account-hash rule above) staging keeps its own
   account.

This module exposes **no nginx variables** — it is purely a cert/challenge-serving
module.

---

## Build & test

OpenSSL ≥ 3.0.0 required. Build as a standard dynamic module:

```sh
cd nginx-<version>
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-autocert-module
make modules
# -> objs/ngx_http_autocert_module.so
```

The single shipped artifact is `ngx_http_autocert_module.so`. Load it with
`load_module modules/ngx_http_autocert_module.so;` and enable it per the config
above.

To compile the in-tree test directives and run the test suite, configure the build
with `AUTOCERT_TEST=1` set in the environment:

```sh
AUTOCERT_TEST=1 ./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-autocert-module
make
```

`AUTOCERT_TEST=1` is consumed at configure time only (it bakes
`-DNGX_AUTOCERT_TEST=1` into the generated Makefile), so it is set on `./configure`
and not repeated on `make`. Use a full `make` here — not `make modules` — because
the e2e suite under `tests/*.sh` runs the actual server binary (`objs/nginx` or
`objs/angie`), which `make modules` does not build.

(The e2e harness uses [Pebble](https://github.com/letsencrypt/pebble) as a local
ACME server.)

---

## See also

- **[Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/)**
  — the walkthrough on deb.myguard.nl.
- **[NGINX modules repository for Debian & Ubuntu](https://deb.myguard.nl/nginx-modules/)**
  — prebuilt packages.
- **Source:** <https://github.com/eilandert/nginx-autocert-module>

---

## License

No license file is shipped with this module at this time.