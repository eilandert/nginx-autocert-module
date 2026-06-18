# nginx-autocert-module

NGINX dynamic module for **automatic ACME certificate provisioning**. Declare
`autocert on;` on a vhost (or globally) and the module obtains and renews a
certificate from an ACME CA (Let's Encrypt by default) for that vhost's
`server_name`s — no certbot, no cron, no manual key handling.

- **ECDSA keys only** (P-384 default, no RSA) — strongest widely-trusted certs.
- **Per-vhost or global** — a `server{}` setting overrides the `http{}` global.
- **Privilege-separated** — keys live in a dedicated helper process, never in
  workers; the on-disk store is root-only (or certbot-compatible) by choice.
- Builds and runs on both **nginx** and **angie**.

> **Status: under construction — end-to-end issuance + serving work.** Done and
> building/loading on nginx + angie: the `autocert` directives and global
> `autocert_*` config model (M0/M2), ECDSA crypto/JWS (M3), the
> privilege-separated helper **process** (M4a), the outbound
> **HTTP/1.1-over-TLS client** (M4b), JSON parsing (M4c), ACME account
> registration (M4d), the HTTP-01 challenge responder (M5), and the full
> **RFC 8555 order flow** — newOrder → authz → http-01 → finalize (ECDSA CSR) →
> download → store (M6). M7 adds **certificate serving**: a `listen 443 ssl;
> autocert on;` server needs **no `ssl_certificate`** — the module gives it a
> self-signed bootstrap cert so the listener comes up, then swaps in the real
> certificate **per-SNI at the TLS handshake**, reloading automatically when a
> renewal rewrites the files (no config reload). M8 adds **timed renewal across
> all configured names**: a scheduler on the helper reads each stored
> certificate's `notAfter` and reissues it once it enters the
> `autocert_renew_before` window (default 7d), writing the fresh cert into the
> store where the per-SNI serve path hot-reloads it — no config reload, no
> downtime. M9 adds **robustness**: each name that fails to provision is held
> off with an exponential per-name backoff (60s, doubling, capped at 1h) so a
> broken name is never hammered, and when the CA replies **HTTP 429 (rate
> limited)** the module honours its **`Retry-After`** header — holding the name
> exactly that long (taking the later of the backoff and the CA's request)
> instead of guessing. Verified end-to-end against Pebble (and a mock CA for
> 429) in CI. M10 adds **TLS-ALPN-01** (RFC 8737, port-80-free validation): M10a
> builds the challenge certificate (SAN + critical `id-pe-acmeIdentifier`), and
> **M10b wires the serve path** — when a client negotiates ALPN `acme-tls/1`
> with an SNI we have a pending challenge for, the handshake serves that
> challenge certificate (from a shared store the helper writes) instead of the
> real one; every other client still gets nginx's normal h2/http negotiation and
> the per-SNI cert. **M10c wires it into the order flow**: with
> `autocert_challenge tls-alpn-01;` the helper selects that challenge, builds the
> challenge cert for the key authorization, publishes it to the serve store,
> answers the CA, and removes it once validated — a full certificate is issued
> with **no port 80 listener anywhere** (verified end-to-end against Pebble in
> CI, validating on a high TLS port with `:80` closed). Still ahead: a packaged
> Debian sub-package (M11).

## Directives

### `autocert on|off [email];`

Valid in `http` (global) and `server` (per-vhost). Optional `email` is the ACME
account contact. A per-vhost value overrides the global one.

```nginx
http {
    autocert on admin@example.com;     # global default for all vhosts

    server {
        listen 443 ssl;
        server_name a.example.com www.a.example.com;
        autocert on;                   # both names provisioned
    }

    server {
        listen 443 ssl;
        server_name c.example.com;
        ssl_certificate /etc/ssl/c.crt;  # real cert -> overridden per-SNI;
        ssl_certificate_key /etc/ssl/c.key;  # kept as the fallback
        autocert off;                    # opt this vhost out (real cert needed)
    }
}
```

> The no-`ssl_certificate` bootstrap is seeded for a **server-level**
> `autocert on` (the form above). A vhost enabled only by the `http`-level
> global `autocert on` still needs its own `autocert on;` line (or an
> `ssl_certificate`) to serve TLS — the global sets the issuance default but
> does not seed every inherited vhost's TLS context.

A `listen ... ssl;` server with `autocert on` needs **no `ssl_certificate`**:
the module gives it a self-signed bootstrap certificate so the listener starts,
then serves the real certificate per-SNI once issued (and on every renewal,
with no reload). If you *do* set `ssl_certificate`, it is kept as the
pre-issuance fallback and overridden per-SNI. Two combinations are rejected at
config time: a `listen ssl;` server with **`autocert off` and no
`ssl_certificate`** (nothing would serve it), and `autocert on` together with a
**variable** `ssl_certificate` (e.g. `ssl_certificate $var;` — the module
can't honour the dynamic lookup).

### Global tuning knobs

These are `http{}`-only (a single ACME policy for the instance):

```nginx
autocert_ca <url>;                  # ACME directory URL
                                    #   default: Let's Encrypt production
autocert_renew_before 7d;           # renew this long before expiry (default 7d)
autocert_key_type secp384r1;        # secp384r1 (default) | secp256r1 — ECDSA only
autocert_store secure|certbot;      # secure = 0700 root-only (default)
                                    #   certbot = live/ + archive/ symlink layout
autocert_path <dir>;                # store location (default: autocert)
autocert_challenge http-01|tls-alpn-01;  # default: http-01

# Outbound ACME transport (used by the helper to reach the CA):
autocert_resolver 1.1.1.1 8.8.8.8;       # DNS server(s) to resolve the CA host.
                                         #   If unset, the http{}-level `resolver`
                                         #   directive is used as a fallback;
                                         #   one of the two is required to reach
                                         #   a CA by name.
autocert_resolver_timeout 30s;           # DNS query timeout (default 30s)
autocert_ca_certificate <file>;          # PEM trust bundle to verify the CA
                                         #   (default: system trust store —
                                         #   correct for Let's Encrypt; set this
                                         #   only for a private/test CA, e.g.
                                         #   Pebble)
```

> The ACME server's certificate is **always verified** (hostname + chain). With
> no `autocert_ca_certificate` the system CA store is used; a private CA (such as
> Pebble for testing) must be supplied explicitly.

### Which names get provisioned

For every vhost with `autocert on`, the module collects its concrete
`server_name`s (deduplicated across vhosts). **Skipped**: vhosts set `autocert
off`, the empty catch-all `""`, and wildcard (`*.x` / `.x`) or regex (`~…`)
`server_name`s — a single ACME order can't cover those (DNS-01 wildcard support
is deferred). The resolved name set is published to a shared-memory zone for the
ACME helper to consume.

## Architecture (target)

- A single **helper process** (master-spawned) runs the ACME state machine and
  holds the account + certificate private keys.
- HTTP-01 challenges are served **transparently** on port 80 (no location
  block needed); TLS-ALPN-01 is offered for port-80-free setups.
- Certificates are loaded **per-SNI at TLS handshake** from the store, so renewal
  needs no config reload.

## Build

Dynamic module:

```sh
cd nginx-<version>
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/path/to/nginx-autocert-module
make modules
# -> objs/ngx_http_autocert_module.so, load with `load_module`.
```

## See also

- Repo: <https://github.com/eilandert/nginx-autocert-module>
<!-- TODO: cross-link blog article / Docker README / Docker Hub when they exist -->
