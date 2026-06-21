# nginx-autocert-module

[![Build & Test](https://github.com/eilandert/nginx-autocert-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/eilandert/nginx-autocert-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/codeql.yml)
[![Security Scanners](https://github.com/eilandert/nginx-autocert-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/eilandert/nginx-autocert-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/eilandert/nginx-autocert-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/eilandert/nginx-autocert-module/actions/workflows/valgrind.yml)

**Automatic TLS certificates for NGINX — built into the server.**

Write `autocert on;` on a vhost and NGINX obtains, serves, and renews a
certificate from an ACME CA (Let's Encrypt by default) for that vhost's
`server_name`s. No certbot, no cron, no deploy hook, no reload. The list of
domains *is* your existing config.

- **No certbot, no cron** — a complete ACME client runs inside NGINX itself.
- **No reload on renewal** — certs load per-SNI at the TLS handshake and
  hot-swap the instant a renewal rewrites the file. Zero downtime.
- **Worker-0 ACME engine** — the ACME state machine runs on a worker-0 timer;
  certificate private keys never leave the worker process pool.
- **ECDSA only** (P-384 default, P-256 optional) — no RSA.
- **HTTP-01 and TLS-ALPN-01** — the latter validates with **no port 80** open.
- **Builds on nginx and Angie** (Angie is compile-checked only — it has its own
  native `acme`).

> 📖 New here? Read the walkthrough:
> **[Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/)**
> on deb.myguard.nl.

---

## Quick start

**1. Build the module** against your nginx source:

```sh
cd nginx-<version>
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-autocert-module
make modules
# -> objs/ngx_http_autocert_module.so       (directives + serving)
```

Requires OpenSSL 3.0.0 or newer.

**2. Load it** and turn it on:

```nginx
load_module modules/ngx_http_autocert_module.so;

events {}

http {
    resolver 1.1.1.1;                    # the ACME engine needs DNS to reach the CA
    autocert on admin@example.com;       # ACME account contact

    server {
        listen 443 ssl;
        server_name example.com www.example.com;
        autocert on;                     # both names get a certificate
        # note: no ssl_certificate needed
    }
}
```

That's it. The listener starts behind a self-signed bootstrap certificate, the
module provisions the real one in the background, and it gets served per-SNI as
soon as it's issued — and on every renewal — without a reload.

---

## How it works

1. **Starts immediately.** A `listen ssl; autocert on;` server with no
   `ssl_certificate` comes up behind a self-signed **bootstrap certificate**, so
   nothing fails while you wait for issuance.
2. **Provisions in the background.** A worker-0 timer runs the full
   [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) ACME order flow for
   each `server_name`: account → order → challenge → finalize (ECDSA CSR) →
   download → store.
3. **Serves per-SNI.** Once issued, the real certificate is loaded at the TLS
   handshake and replaces the bootstrap cert. The store is re-read only when the
   file's mtime changes — so a renewal takes effect on the next handshake, **no
   reload, no dropped connections**.
4. **Renews itself.** The worker-0 timer sweeps and reissues each certificate
   once it enters the `autocert_renew_before` window (7 days by default). Failed
   names back off (exponential, 60 s → 1 h); a CA `HTTP 429` `Retry-After` is
   honoured.

**Three challenge types.** HTTP-01 (default) is answered transparently on port 80
by a built-in handler — no `location` block. TLS-ALPN-01
([RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737)),
`autocert_challenge tls-alpn-01;`, validates entirely inside the TLS handshake,
so **port 80 can stay closed**. DNS-01, `autocert_challenge dns-01;`, publishes a
`_acme-challenge` TXT record through an operator hook script — the only challenge
that can issue **wildcard** certificates (`*.example.com`), and it needs no
inbound port at all. See [DNS-01 challenge](#dns-01-challenge-wildcards) below.

The whole flow is verified end-to-end against
[Pebble](https://github.com/letsencrypt/pebble) in CI, plus fuzzing, Valgrind,
CodeQL and static analysis.

---

## Directives

### `autocert on | off [email];`

The on/off switch (plus the [CA selector](#ca-selector-http-default-overridable-per-server)
directives) may live inside `server{}`. Optional `email` is the ACME account
contact. A `server{}` value overrides the `http{}` global.

```nginx
http {
    autocert on admin@example.com;       # global default for all vhosts

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
do set one, it's kept as the pre-issuance fallback and overridden per-SNI.

> **Gotcha:** the no-cert bootstrap is seeded only for a **server-level**
> `autocert on`. A vhost enabled purely by the `http{}`-level global still needs
> its own `autocert on;` line (or an `ssl_certificate`) to serve TLS.

Two configs are rejected at parse time: a `listen ssl;` server with `autocert
off` **and** no `ssl_certificate` (nothing would serve it), and `autocert on`
together with a **variable** `ssl_certificate` (e.g. `ssl_certificate $var;`).

### CA selector (`http{}` default, overridable per `server{}`)

Which CA signs, and the credentials/trust bound to it. Settable at `http{}` as
the instance default **and** inside a `server{}` to pin that vhost to a different
CA — see [Multiple CAs in one instance](#multiple-cas-in-one-instance). All
optional.

| Directive | Default | Purpose |
|---|---|---|
| `autocert_ca <url>;` | Let's Encrypt production | ACME directory URL |
| `autocert_staging on\|off;` | `off` | use Let's Encrypt **staging** CA instead — see note |
| `autocert_ca_certificate <file>;` | system trust store | PEM bundle to verify the CA |
| `autocert_eab_kid <key-id>;` | *(none)* | EAB key identifier — see below |
| `autocert_eab_hmac_key <base64url>;` | *(none)* | EAB HMAC key (base64url) — see below |

### Global tuning knobs (`http{}` only)

Instance-wide; one value per nginx instance. All optional.

| Directive | Default | Purpose |
|---|---|---|
| `autocert_renew_before <time>;` | `7d` | renew this long before expiry |
| `autocert_key_type secp384r1\|secp256r1;` | `secp384r1` | ECDSA curve (no RSA) |
| `autocert_store secure\|certbot;` | `secure` | on-disk layout. `secure`: `<path>/<domain>/{privkey,fullchain}.pem`. `certbot`: `<path>/live/<domain>/{privkey,cert,chain,fullchain}.pem` (flat live/, real files — no archive/ + symlinks) |
| `autocert_path <dir>;` | `autocert` | store location (relative to the nginx prefix) |
| `autocert_challenge http-01\|tls-alpn-01\|dns-01;` | `http-01` | challenge type — `dns-01` needs the hook directives below |
| `autocert_resolver <addr>...;` | the `http{}` `resolver` | DNS used to reach the CA |
| `autocert_resolver_timeout <time>;` | `30s` | DNS query timeout |
| `autocert_dns_hook_add <path>;` | *(none)* | DNS-01 only: absolute path of the publish-TXT hook — see below |
| `autocert_dns_hook_remove <path>;` | *(none)* | DNS-01 only: absolute path of the remove-TXT hook |
| `autocert_dns_propagation_delay <time>;` | `10s` | DNS-01 only: wait after publishing before asking the CA to validate |
| `autocert_dns_hook_timeout <time>;` | `30s` | DNS-01 only: max runtime for a single hook exec before it is killed |

> `autocert_key_type` takes the OpenSSL curve names `secp384r1` / `secp256r1`,
> not `p384` / `p256`. The ACME server's certificate is **always** verified
> (chain + hostname); set `autocert_ca_certificate` only for a private/test CA
> such as Pebble.

> **`autocert_staging on`** is a shorthand for
> `autocert_ca https://acme-staging-v02.api.letsencrypt.org/directory`.
> It is mutually exclusive with `autocert_ca` — nginx will refuse to start if
> both appear in the same scope (`http{}` or one `server{}`). Staging
> certificates are issued via
> the real ACME protocol and follow the same flow as production, but they are
> signed by the *Fake LE* intermediate and are **not trusted by browsers**.
> They consume no production rate-limit quota, making them suitable for
> CI/CD pipelines that exercise the full issuance path before go-live.

### External Account Binding (commercial CAs)

Some CAs (ZeroSSL, Sectigo, Google Trust Services) require **External Account
Binding** (RFC 8555 §7.3.4): the ACME account must be tied to an account you
already hold with the CA, proven by a key-id + HMAC key the CA hands you from
its dashboard.

```nginx
http {
    autocert_ca         https://acme.zerossl.com/v2/DV90;
    autocert_eab_kid     "your-eab-key-id";
    autocert_eab_hmac_key "base64url-hmac-key-from-the-CA-dashboard";
}
```

The HMAC key is the value as the CA gives it — base64url-encoded (no padding).
`autocert_eab_kid` and `autocert_eab_hmac_key` are **both-or-neither**: setting
only one fails config. The binding is computed and sent **only** on account
registration (`newAccount`); ordinary order/renewal requests are unaffected.
Let's Encrypt does not use EAB — leave both unset for it.

### Multiple CAs in one instance

The CA selector directives (`autocert_ca`, `autocert_staging`,
`autocert_ca_certificate`, `autocert_eab_kid`, `autocert_eab_hmac_key`) may be
set inside a `server{}` block to pin that vhost to a different CA than the
`http{}` default. Each distinct CA gets its own ACME account, account key
(`<path>/accounts/<hash>/account.key`), and renewal engine; one instance can
issue against several CAs at once.

```nginx
http {
    autocert on admin@example.com;
    autocert_ca https://acme-v02.api.letsencrypt.org/directory;   # default CA

    server {                       # uses the http{} default (Let's Encrypt)
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

**Inheritance rule (important).** A `server{}` that sets **either** `autocert_ca`
**or** `autocert_staging` owns its entire CA selector and inherits **nothing**
else from the `http{}` default — not the trust bundle, not the EAB credentials.
This is deliberate: inheriting CA-A's pinned root or EAB key for CA-B would send
the wrong credentials or pin the wrong root. So a vhost that overrides the CA
**must also repeat** any `autocert_ca_certificate` / `autocert_eab_*` it needs,
inside that same `server{}`. A vhost that does **not** override the CA inherits
the whole `http{}` selector as usual.

> A single `server_name` must not be claimed by two vhosts that resolve to
> different CAs — there is one stored certificate per name. Keep each name under
> one CA.

### DNS-01 challenge (wildcards)

DNS-01 proves control by publishing a TXT record at
`_acme-challenge.<domain>`. It is the only challenge that can issue **wildcard**
certificates (`*.example.com`) and needs **no inbound port** — useful behind a
load balancer or on a host that exposes neither 80 nor 443 to the CA.

Because every DNS provider has a different API, publishing is delegated to two
operator **hook scripts** you supply. Both are required when
`autocert_challenge dns-01;`, and both must be **absolute paths**:

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

**Hook contract.** Each hook is run `fork()` + `execve()` (no shell) with:

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

- **The hook runs on the ACME worker** and blocks it for the duration of the
  exec (bounded by `autocert_dns_hook_timeout`). Keep hooks fast — a single API
  call, not a propagation poll. The propagation *wait* is handled separately and
  asynchronously by `autocert_dns_propagation_delay`.
- **The hook inherits nginx's environment** by design, so provider credentials
  can be passed via env (e.g. `DNS_API_TOKEN`), the certbot-manual convention.
- The record is removed via the remove-hook once the authorization settles
  (cleanup failure is non-fatal — the record expires by TTL).

### Which names get provisioned

The module collects the concrete `server_name`s of every vhost with `autocert
on` (deduplicated). **Wildcards** (`*.example.com`) are provisioned **only under
`autocert_challenge dns-01;`** (RFC 8555 forbids HTTP-01/TLS-ALPN-01 for a
wildcard); the cert is stored under a `_wildcard_.example.com` directory and
served for any single-label subdomain SNI. **Skipped:** vhosts set `autocert
off`, the empty catch-all `""`, a leading-dot (`.x`) or regex (`~…`) name, and a
wildcard when the challenge is not dns-01 — a single ACME order can't cover
those.

---

## Architecture

- A **worker-0 timer** runs the ACME state machine. Certificate and account keys
  are managed inside the worker process; no separate helper process is needed.
  (This matches Angie's native `acme` and the official Rust `nginx-acme`, which
  also drive ACME from a worker rather than a privileged helper.)
- **Exactly one driver** runs at a time. The engine is armed only on worker 0,
  and an `flock` on `<autocert_path>/.driver.lock` serializes generations across
  a reload or `USR2` hot upgrade — the retiring worker 0 holds the lock until it
  exits, then the fresh worker 0 takes over (within a few seconds) and runs its
  first renewal sweep. So no two processes ever race the account nonce or submit
  duplicate orders.
- The ACME engine reaches the CA over a **verified TLS** connection (its own
  resolver + HTTP/1.1 client); challenge tokens and cert state are held in a
  shared-memory zone accessible to all workers.
- HTTP-01 challenges are served transparently on port 80; TLS-ALPN-01 needs no
  port 80 at all.
- Certificates are loaded **per-SNI at the TLS handshake**, so renewal needs no
  config reload.

The addon ships a **single** dynamic module: `ngx_http_autocert_module.so`.

### Permissions — the store must be writable by the worker user

Because the ACME engine now runs in worker 0 (not a privileged helper), the
**worker user owns the key material**: `account.key`, the per-domain cert store
under `autocert_path`, and the `.driver.lock` file are all created and written by
the user NGINX drops to (the `user` directive; default `nobody` when started as
root). Make sure that directory is writable by that user:

```sh
mkdir -p /var/lib/autocert
chown <worker-user>:<worker-group> /var/lib/autocert
chmod 0700 /var/lib/autocert
```

If you are **upgrading** from a build that used the old root-owned helper, the
existing `account.key` and store files are owned by `root` and the worker cannot
read or rewrite them — `chown -R <worker-user> <autocert_path>` once before
restarting (the account key is also rejected if it is not owned by the running
user).

---

## Status

**Works today:** full issuance + renewal on nginx mainline, HTTP-01,
TLS-ALPN-01 and DNS-01 (incl. **wildcard** `*.x` via operator hooks), EAB for
commercial CAs, **per-vhost multiple CAs** (one ACME account + engine per CA),
per-SNI serving with bootstrap + zero-reload hot-swap, ECDSA P-384/P-256,
worker-owned `secure` and `certbot` store layouts, `badNonce` retry, per-name
backoff, and `429` / `Retry-After` awareness.

**Not yet:** a packaged Debian sub-package. Both nginx and Angie are fully
supported and run the same end-to-end test suite; on Angie the `autocert`
directive coexists with Angie's own native `acme` (pick whichever you prefer).

---

## See also

- 📝 Article: [Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/) — what it is and how it works, in plain English.
- 📦 [NGINX modules repository for Debian & Ubuntu](https://deb.myguard.nl/nginx-modules/) — 100+ ready-built NGINX modules, no compiling.
- 💻 Source: <https://github.com/eilandert/nginx-autocert-module>
