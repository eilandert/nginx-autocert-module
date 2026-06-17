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

> **Status: under construction.** M0 (module scaffold + `autocert` directive)
> is in place and builds/loads on nginx + angie. ACME issuance lands in later
> milestones — see the roadmap. Not yet usable for real certificates.

## Directive (current)

```nginx
autocert on|off [email];
```

Valid in `http` (global) and `server` (per-vhost). Optional `email` is the ACME
account contact. A per-vhost value overrides the global one.

```nginx
http {
    autocert on admin@example.com;     # global default for all vhosts

    server {
        listen 443 ssl;
        server_name a.example.com;
        autocert on;                   # inherits/uses the global account
    }

    server {
        listen 443 ssl;
        server_name b.example.com;
        autocert off;                   # opt this vhost out
    }
}
```

## Planned directives (later milestones)

```nginx
autocert_ca <url>;                  # default: Let's Encrypt production
autocert_renew_before 7d;           # renew this long before expiry
autocert_key_type secp384r1;        # secp384r1 (default) | secp256r1
autocert_store secure|certbot;      # 0700 root-only | certbot live/+archive/
autocert_path <dir>;                # store location
autocert_challenge http-01|tls-alpn-01;
```

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
