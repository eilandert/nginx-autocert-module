# nginx-autocert-module

[![Build & Test](https://github.com/eilandert/nginx-autocert-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/eilandert/nginx-autocert-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/codeql.yml)
[![Security Scanners](https://github.com/eilandert/nginx-autocert-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/eilandert/nginx-autocert-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/eilandert/nginx-autocert-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/valgrind.yml)

**Automatic TLS certificates for NGINX — built into the server.**

Write `autocert on;` on a vhost and NGINX obtains, serves, and renews a
certificate from an ACME CA (Let's Encrypt by default) for that vhost's
`server_name`s. No certbot, no cron, no deploy hook, no reload. **Your existing
`server_name` list *is* the domain list** — there is nothing else to maintain.

> 📖 New here? Start with the walkthrough:
> **[Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/)**
> on deb.myguard.nl.

---

## Why

- **No certbot, no cron, no deploy hook** — a complete [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555)
  ACME client runs inside NGINX itself.
- **No reload on renewal** — certificates load per-SNI at the TLS handshake and
  hot-swap the instant a renewal rewrites the file. Zero downtime.
- **Keys stay in the worker** — the ACME engine runs on a worker-0 timer, not a
  privileged helper; private keys never leave the worker process pool.
- **Three challenge types** — HTTP-01, TLS-ALPN-01 (validates with **no port
  80**), and DNS-01 (issues **wildcards**, needs **no inbound port**).
- **Multiple CAs at once** — pin different vhosts to different CAs, each with its
  own account and renewal engine.
- **ECDSA only** — P-384 (default) or P-256, no RSA.
- **nginx *and* Angie** — both are fully supported and run the same end-to-end
  test suite. (On Angie this coexists with Angie's own native `acme`; pick
  whichever you prefer.)

Verified end-to-end against [Pebble](https://github.com/letsencrypt/pebble) in
CI, plus fuzzing, Valgrind, CodeQL, and static analysis.

---

## Quick start

**1. Build** the module against your nginx source (OpenSSL ≥ 3.0.0 required):

```sh
cd nginx-<version>
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-autocert-module
make modules
# -> objs/ngx_http_autocert_module.so
```

**2. Load and enable** it:

```nginx
load_module modules/ngx_http_autocert_module.so;

events {}

http {
    resolver 1.1.1.1;                  # the ACME engine needs DNS to reach the CA
    autocert on admin@example.com;     # ACME account contact

    server {
        listen 443 ssl;
        server_name example.com www.example.com;
        autocert on;                   # both names get a certificate
        # no ssl_certificate needed
    }
}
```

That's it. The listener comes up behind a self-signed bootstrap certificate, the
module provisions the real one in the background, and it is served per-SNI the
moment it is issued — and on every renewal — **without a reload**.

---

## How it works

1. **Starts immediately.** A `listen ssl; autocert on;` server with no
   `ssl_certificate` comes up behind a self-signed **bootstrap certificate**, so
   nothing fails while you wait for issuance.
2. **Provisions in the background.** A worker-0 timer drives the full RFC 8555
   order flow for each `server_name`: account → order → challenge → finalize
   (ECDSA CSR) → download → store.
3. **Serves per-SNI.** The real certificate is loaded at the TLS handshake and
   replaces the bootstrap cert. The store is re-read only when the file's mtime
   changes, so a renewal takes effect on the next handshake — **no reload, no
   dropped connections**.
4. **Renews itself.** The timer sweeps and reissues each certificate once it
   enters the `autocert_renew_before` window (7 days by default). A failed name
   backs off exponentially (60 s → 1 h); a CA `HTTP 429` `Retry-After` is
   honoured.

---

## Configuration

### Turning it on — `autocert on | off [email];`

`autocert` is valid in `http{}` (the instance default) and in `server{}`. The
optional `email` is the ACME account contact. A `server{}` value overrides the
`http{}` global. With per-vhost CAs (see *Multiple CAs* below), the contact is
per-CA: each CA's account uses the first email set by a vhost in that CA group,
and configuring one CA with two different contacts is rejected at startup.

```nginx
http {
    autocert on admin@example.com;       # default for all vhosts

    server {
        listen 443 ssl;
        server_name a.example.com www.a.example.com;
        autocert on;                     # both names provisioned, no cert file
    }

    server {
        listen 443 ssl;
        server_name c.example.com;
        ssl_certificate     /etc/ssl/c.crt;   # real cert kept as fallback,
        ssl_certificate_key /etc/ssl/c.key;   #   overridden per-SNI if enabled
        autocert off;                          # opt this vhost out
    }
}
```

A `listen ssl;` server with `autocert on` needs **no `ssl_certificate`**. If you
set one anyway it is kept as the pre-issuance fallback and overridden per-SNI.

> **Gotcha:** the no-cert bootstrap is seeded only for a **server-level**
> `autocert on`. A vhost enabled purely by the `http{}`-level global still needs
> its own `autocert on;` line (or an `ssl_certificate`) to serve TLS.

Two configs are rejected at parse time: a `listen ssl;` server with `autocert
off` **and** no `ssl_certificate` (nothing would serve it), and `autocert on`
together with a **variable** `ssl_certificate` (e.g. `ssl_certificate $var;`).

### Choosing the CA

These directives select **which CA signs**, plus the trust and credentials bound
to it. They are valid in `http{}` as the instance default **and** inside a
`server{}` to pin that vhost to a different CA. All optional.

| Directive | Default | Purpose |
|---|---|---|
| `autocert_ca <url>;` | Let's Encrypt production | ACME directory URL |
| `autocert_staging on\|off;` | `off` | use Let's Encrypt **staging** instead of `autocert_ca` |
| `autocert_ca_certificate <file>;` | system trust store | PEM bundle to verify the CA (for a private/test CA such as Pebble) |
| `autocert_eab_kid <key-id>;` | *(none)* | EAB key identifier (commercial CAs) |
| `autocert_eab_hmac_key <base64url>;` | *(none)* | EAB HMAC key, base64url |

> The ACME server's certificate is **always** verified (chain + hostname); set
> `autocert_ca_certificate` only when the CA is not in the system trust store.
> `autocert_key_type` takes OpenSSL curve names (`secp384r1` / `secp256r1`), not
> `p384` / `p256`.

**Staging.** `autocert_staging on;` is shorthand for
`autocert_ca https://acme-staging-v02.api.letsencrypt.org/directory`. It is
mutually exclusive with `autocert_ca` in the same scope (`http{}` or one
`server{}`) — nginx refuses to start if both appear together. Staging certs run
the full ACME flow but are signed by the *Fake LE* intermediate (not
browser-trusted) and consume no production rate-limit quota — ideal for CI.

**External Account Binding (commercial CAs).** Some CAs (ZeroSSL, Sectigo,
Google Trust Services) require [EAB](https://datatracker.ietf.org/doc/html/rfc8555#section-7.3.4):
the ACME account is tied to an account you already hold, proven with a key-id +
HMAC key from the CA dashboard.

```nginx
http {
    autocert_ca          https://acme.zerossl.com/v2/DV90;
    autocert_eab_kid     "your-eab-key-id";
    autocert_eab_hmac_key "base64url-hmac-key-from-the-CA-dashboard";
}
```

The HMAC key is the value as the CA gives it (base64url, no padding).
`autocert_eab_kid` and `autocert_eab_hmac_key` are **both-or-neither** — setting
only one fails config. The binding is sent **only** at account registration
(`newAccount`); orders and renewals are unaffected. Let's Encrypt does not use
EAB — leave both unset for it.

**Multiple CAs in one instance.** Set the CA-selector directives inside a
`server{}` to pin that vhost to a different CA than the `http{}` default. Each
distinct CA gets its own ACME account, account key
(`<path>/accounts/<hash>/account.key`), and renewal engine.

```nginx
http {
    autocert on admin@example.com;
    autocert_ca https://acme-v02.api.letsencrypt.org/directory;   # default CA

    server {                       # inherits the http{} default (Let's Encrypt)
        listen 443 ssl;
        server_name a.example.com;
    }

    server {                       # pinned to a different CA + EAB
        listen 443 ssl;
        server_name b.example.com;
        autocert_ca          https://acme.zerossl.com/v2/DV90;
        autocert_eab_kid     "your-eab-key-id";
        autocert_eab_hmac_key "base64url-hmac-key";
    }
}
```

> **Inheritance rule.** A `server{}` that sets **either** `autocert_ca` **or**
> `autocert_staging` owns its entire CA selector and inherits **nothing** else
> from the `http{}` default — not the trust bundle, not the EAB credentials.
> This is deliberate: inheriting CA-A's pinned root or EAB key for CA-B would
> send the wrong credentials or pin the wrong root. A vhost that overrides the CA
> **must repeat** any `autocert_ca_certificate` / `autocert_eab_*` it needs,
> inside that same `server{}`. A vhost that does *not* override the CA inherits
> the whole `http{}` selector as usual.
>
> One `server_name` must resolve to one CA: a name claimed by two vhosts with
> different CAs is rejected at config time (there is one stored certificate per
> name).

### Tuning (`http{}` only)

Instance-wide knobs — one value per nginx instance. All optional.

| Directive | Default | Purpose |
|---|---|---|
| `autocert_renew_before <time>;` | `7d` | renew this long before expiry |
| `autocert_key_type secp384r1\|secp256r1;` | `secp384r1` | ECDSA curve (no RSA) |
| `autocert_store secure\|certbot;` | `secure` | on-disk layout — see [Storage](#storage) |
| `autocert_path <dir>;` | `autocert` | store location (relative to the nginx prefix) |
| `autocert_challenge http-01\|tls-alpn-01\|dns-01;` | `http-01` | challenge type |
| `autocert_resolver <addr>...;` | the `http{}` `resolver` | DNS used to reach the CA |
| `autocert_resolver_timeout <time>;` | `30s` | DNS query timeout |
| `autocert_dns_hook_add <path>;` | *(none)* | DNS-01: absolute path of the publish-TXT hook |
| `autocert_dns_hook_remove <path>;` | *(none)* | DNS-01: absolute path of the remove-TXT hook |
| `autocert_dns_propagation_delay <time>;` | `10s` | DNS-01: wait after publishing before validating |
| `autocert_dns_hook_timeout <time>;` | `30s` | DNS-01: max runtime of one hook exec before it is killed |

### Challenges

The CA proves you control a name via a **challenge**. Pick one with
`autocert_challenge` (default `http-01`).

- **`http-01`** — answered transparently on **port 80** by a built-in handler. No
  `location` block, nothing to configure.
- **`tls-alpn-01`** ([RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737)) —
  validated entirely inside the TLS handshake, so **port 80 can stay closed**.
- **`dns-01`** — publishes a `_acme-challenge` TXT record via operator hooks. The
  only challenge that issues **wildcards**, and it needs **no inbound port** —
  see below.

#### DNS-01 and wildcards

DNS-01 proves control by publishing a TXT record at `_acme-challenge.<domain>`.
Because every provider's API differs, publishing is delegated to two operator
**hook scripts** you supply. Both are required under `autocert_challenge dns-01;`
and both must be **absolute paths**:

```nginx
http {
    autocert on admin@example.com;
    autocert_challenge dns-01;
    autocert_dns_hook_add    /etc/nginx/acme/publish.sh;
    autocert_dns_hook_remove /etc/nginx/acme/unpublish.sh;
    autocert_dns_propagation_delay 30s;   # let the record propagate first

    server {
        listen 443 ssl;
        server_name example.com *.example.com;   # wildcard needs dns-01
        autocert on;
    }
}
```

**Hook contract.** Each hook is run via `fork()` + `execve()` (no shell) with:

```
argv = { <hook-path>, "_acme-challenge.<domain>", "<txt-value>" }
```

For a wildcard `*.example.com` the record name is the base
(`_acme-challenge.example.com`). The hook **must exit 0 on success**; a non-zero
exit (or a timeout past `autocert_dns_hook_timeout`) fails the order. Example
publish hook for a provider with an HTTP API:

```bash
#!/usr/bin/env bash
set -euo pipefail
# $1 = _acme-challenge.example.com   $2 = the TXT value
curl -fsS -X POST "https://dns.example/api/txt" \
     -H "Authorization: Bearer ${DNS_API_TOKEN}" \
     -d "name=${1}." -d "value=${2}" >/dev/null
```

Caveats:

- **The hook runs on the ACME worker** and blocks it for the exec (bounded by
  `autocert_dns_hook_timeout`). Keep hooks fast — a single API call, not a
  propagation poll. The propagation *wait* is handled separately and
  asynchronously by `autocert_dns_propagation_delay`.
- **The hook inherits nginx's environment** by design, so provider credentials
  can be passed via env (e.g. `DNS_API_TOKEN`) — the certbot-manual convention.
- The record is removed by the remove-hook once the authorization settles
  (cleanup failure is non-fatal — the record expires by TTL).

### Which names get provisioned

The module collects the concrete `server_name`s of every vhost with `autocert
on` (deduplicated). **Wildcards** (`*.example.com`) are provisioned **only under
`autocert_challenge dns-01;`** (RFC 8555 forbids HTTP-01/TLS-ALPN-01 for a
wildcard); the cert is stored under a `_wildcard_.example.com` directory and
served for any single-label subdomain SNI. **Skipped:** vhosts with `autocert
off`, the empty catch-all `""`, a leading-dot (`.x`) or regex (`~…`) name, and a
wildcard under a non-dns-01 challenge — a single ACME order can't cover those.

---

## Storage

`autocert_path` (default `autocert`, relative to the nginx prefix) holds the
account key(s) and the issued certificates. `autocert_store` picks the layout:

| Mode | Layout |
|---|---|
| `secure` (default) | `<path>/<domain>/{privkey,fullchain}.pem` |
| `certbot` | `<path>/live/<domain>/{privkey,cert,chain,fullchain}.pem` (flat `live/`, real files — no `archive/` + symlinks) |

Account keys live under `<path>/accounts/<ca-hash>/account.key`, one per CA.

### Permissions — the store must be writable by the worker user

The ACME engine runs in **worker 0**, so the **worker user owns the key
material**: `account.key`, the per-domain cert store, and the `.driver.lock` file
are all created and written by the user NGINX drops to (the `user` directive;
default `nobody` when started as root). Make that directory writable by it:

```sh
mkdir -p /var/lib/autocert
chown <worker-user>:<worker-group> /var/lib/autocert
chmod 0700 /var/lib/autocert
```

> **Upgrading from the old root-owned helper?** Existing `account.key` and store
> files are owned by `root` and the worker cannot read or rewrite them. Run
> `chown -R <worker-user> <autocert_path>` once before restarting (an account key
> not owned by the running user is rejected).

---

## Architecture

- A **worker-0 timer** runs the ACME state machine. Certificate and account keys
  are managed inside the worker process — no separate helper. (This matches
  Angie's native `acme` and the official Rust `nginx-acme`, which also drive ACME
  from a worker rather than a privileged helper.)
- **Exactly one driver** runs at a time. The engine is armed only on worker 0,
  and an `flock` on `<autocert_path>/.driver.lock` serializes generations across
  a reload or `USR2` hot upgrade — the retiring worker 0 holds the lock until it
  exits, then the fresh worker 0 takes over (within seconds) and runs its first
  sweep. No two processes ever race the account nonce or submit duplicate orders.
- With **multiple CAs**, the one driver runs an independent engine per CA (its
  own account, key, and renewal schedule), still under the single driver lock —
  one ACME order is in flight at a time across all CAs.
- The engine reaches each CA over a **verified TLS** connection (its own resolver
  + HTTP/1.1 client); challenge tokens and cert state live in a shared-memory
  zone accessible to all workers.
- Certificates are loaded **per-SNI at the TLS handshake**, so renewal needs no
  config reload.
- A **config reload** is handled in both run modes. In the normal master+workers
  model nginx forks fresh workers, so the new worker 0 simply re-arms the engine.
  In **`master_process off`** (single-process) mode the process survives the
  reload, so the module rebinds the driver and the per-SNI serve gate to the new
  configuration in place — added/removed issuance names take effect, and any
  in-flight ACME request is cancelled cleanly before the old state is torn down.

The addon ships a **single** dynamic module: `ngx_http_autocert_module.so`.

---

## Status

**Works today:** full issuance + renewal on nginx mainline **and Angie** (same
end-to-end suite on both); HTTP-01, TLS-ALPN-01, and DNS-01 (incl. **wildcards**
via operator hooks); EAB for commercial CAs; **per-vhost multiple CAs** (one
account + engine per CA); per-SNI serving with bootstrap + zero-reload hot-swap;
ECDSA P-384/P-256; `secure` and `certbot` store layouts; `badNonce` retry,
per-name backoff, and `429` / `Retry-After` awareness.

**Not yet:** a packaged Debian sub-package.

---

## See also

- 📝 Article: [Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/) — what it is and how it works, in plain English.
- 📦 [NGINX modules repository for Debian & Ubuntu](https://deb.myguard.nl/nginx-modules/) — 100+ ready-built NGINX modules, no compiling.
- 💻 Source: <https://github.com/eilandert/nginx-autocert-module>
