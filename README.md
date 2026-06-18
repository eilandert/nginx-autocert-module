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

> **Status: under construction.** M0 (`autocert` directive), M2 (the global
> `autocert_*` config model + enabled-name collection), M3 (ECDSA crypto/JWS
> primitives), M4a (the privilege-separated helper **process**) and M4b (the
> outbound **HTTP/1.1-over-TLS client**) are in place and build/load on nginx +
> angie. The directives parse and validate, the set of `server_name`s to
> provision is resolved at config time, the master runs a dedicated helper
> process that survives reloads and crashes, and that helper can now reach the
> ACME server: it resolves the CA hostname (`ngx_resolver`), connects, completes
> a verified TLS handshake, and performs an HTTP request — proven by fetching the
> CA **directory** at startup. The full ACME issuance flow (account, orders,
> challenges, certificate download) lands in M4c+. Not yet usable for real
> certificates.

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
        server_name b.example.com;
        autocert off;                   # opt this vhost out
    }
}
```

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
