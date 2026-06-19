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
- **Privilege-separated** — a dedicated helper process holds every private key;
  workers never touch key material.
- **ECDSA only** (P-384 default, P-256 optional) — no RSA.
- **HTTP-01 and TLS-ALPN-01** — the latter validates with **no port 80** open.
- **Builds on nginx and Angie** (Angie is compile-checked only — it has its own
  native `acme`).

> 📖 New here? Read the walkthrough:
> **[Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/)**
> on deb.myguard.nl.

---

## Quick start

**1. Build the two modules** against your nginx source:

```sh
cd nginx-<version>
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-autocert-module
make modules
# -> objs/ngx_autocert_process_module.so   (the helper)
#    objs/ngx_http_autocert_module.so       (directives + serving)
```

Requires OpenSSL 3.0.0 or newer.

**2. Load both** (helper first) and turn it on:

```nginx
load_module modules/ngx_autocert_process_module.so;
load_module modules/ngx_http_autocert_module.so;

events {}

http {
    resolver 1.1.1.1;                    # the helper needs DNS to reach the CA
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
helper provisions the real one in the background, and it gets served per-SNI as
soon as it's issued — and on every renewal — without a reload.

---

## How it works

1. **Starts immediately.** A `listen ssl; autocert on;` server with no
   `ssl_certificate` comes up behind a self-signed **bootstrap certificate**, so
   nothing fails while you wait for issuance.
2. **Provisions in the background.** A single master-spawned **helper process** —
   the only process that ever holds the account and certificate private keys —
   runs the full [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) order
   flow for each `server_name`: account → order → challenge → finalize (ECDSA
   CSR) → download → store.
3. **Serves per-SNI.** Once issued, the real certificate is loaded at the TLS
   handshake and replaces the bootstrap cert. The store is re-read only when the
   file's mtime changes — so a renewal takes effect on the next handshake, **no
   reload, no dropped connections**.
4. **Renews itself.** The helper sweeps on a timer and reissues each certificate
   once it enters the `autocert_renew_before` window (7 days by default). Failed
   names back off (exponential, 60 s → 1 h); a CA `HTTP 429` `Retry-After` is
   honoured.

**Two challenge types.** HTTP-01 (default) is answered transparently on port 80
by a built-in handler — no `location` block. TLS-ALPN-01
([RFC 8737](https://datatracker.ietf.org/doc/html/rfc8737)),
`autocert_challenge tls-alpn-01;`, validates entirely inside the TLS handshake,
so **port 80 can stay closed**.

The whole flow is verified end-to-end against
[Pebble](https://github.com/letsencrypt/pebble) in CI, plus fuzzing, Valgrind,
CodeQL and static analysis.

---

## Directives

### `autocert on | off [email];`

The only directive valid inside `server{}`. Optional `email` is the ACME account
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

### Global tuning knobs (`http{}` only)

One ACME policy per instance. All optional.

| Directive | Default | Purpose |
|---|---|---|
| `autocert_ca <url>;` | Let's Encrypt production | ACME directory URL |
| `autocert_staging on\|off;` | `off` | use Let's Encrypt **staging** CA instead — see note |
| `autocert_renew_before <time>;` | `7d` | renew this long before expiry |
| `autocert_key_type secp384r1\|secp256r1;` | `secp384r1` | ECDSA curve (no RSA) |
| `autocert_store secure;` | `secure` | on-disk layout (`certbot` is rejected until implemented) |
| `autocert_path <dir>;` | `autocert` | store location (relative to the nginx prefix) |
| `autocert_challenge http-01\|tls-alpn-01;` | `http-01` | challenge type |
| `autocert_resolver <addr>...;` | the `http{}` `resolver` | DNS used to reach the CA |
| `autocert_resolver_timeout <time>;` | `30s` | DNS query timeout |
| `autocert_ca_certificate <file>;` | system trust store | PEM bundle to verify the CA |

> `autocert_key_type` takes the OpenSSL curve names `secp384r1` / `secp256r1`,
> not `p384` / `p256`. The ACME server's certificate is **always** verified
> (chain + hostname); set `autocert_ca_certificate` only for a private/test CA
> such as Pebble.

> **`autocert_staging on`** is a shorthand for
> `autocert_ca https://acme-staging-v02.api.letsencrypt.org/directory`.
> It is mutually exclusive with `autocert_ca` — nginx will refuse to start if
> both appear in the same `http {}` block. Staging certificates are issued via
> the real ACME protocol and follow the same flow as production, but they are
> signed by the *Fake LE* intermediate and are **not trusted by browsers**.
> They consume no production rate-limit quota, making them suitable for
> CI/CD pipelines that exercise the full issuance path before go-live.

### Which names get provisioned

The module collects the concrete `server_name`s of every vhost with `autocert
on` (deduplicated). **Skipped:** vhosts set `autocert off`, the empty catch-all
`""`, and wildcard (`*.x` / `.x`) or regex (`~…`) names — a single ACME order
can't cover those (wildcards need DNS-01, which isn't supported yet).

---

## Architecture

- A single master-spawned **helper process** runs the ACME state machine and
  holds the account + certificate private keys. Workers never touch keys.
- The helper reaches the CA over a **verified TLS** connection (its own resolver
  + HTTP/1.1 client); challenge tokens and cert state pass to workers through a
  shared-memory zone.
- HTTP-01 challenges are served transparently on port 80; TLS-ALPN-01 needs no
  port 80 at all.
- Certificates are loaded **per-SNI at the TLS handshake**, so renewal needs no
  config reload.

The addon ships **two** dynamic modules: `ngx_autocert_process_module` (CORE —
the helper) and `ngx_http_autocert_module` (HTTP — directives + serving). Load
the helper first.

---

## Status

**Works today:** full issuance + renewal on nginx mainline, HTTP-01 and
TLS-ALPN-01, per-SNI serving with bootstrap + zero-reload hot-swap, ECDSA
P-384/P-256, secure root-only store, `badNonce` retry, per-name backoff, and
`429` / `Retry-After` awareness.

**Not yet:** wildcard / DNS-01 certificates, multiple CAs / EAB, the `certbot`
store layout, and a packaged Debian sub-package. Angie is compile-checked only —
on Angie, use its native `acme` directive instead.

---

## See also

- 📝 Article: [Automatic TLS Certs, No Certbot](https://deb.myguard.nl/2026/06/nginx-autocert-module/) — what it is and how it works, in plain English.
- 📦 [NGINX modules repository for Debian & Ubuntu](https://deb.myguard.nl/nginx-modules/) — 100+ ready-built NGINX modules, no compiling.
- 💻 Source: <https://github.com/eilandert/nginx-autocert-module>
