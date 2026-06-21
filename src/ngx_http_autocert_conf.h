/*
 * ngx_http_autocert_conf — the autocert HTTP module's config struct
 * definitions, shared between the HTTP module itself and the small accessor TU
 * (ngx_autocert_conf.c) that the CORE helper module links in.
 *
 * Why a shared header instead of a cross-.so symbol: the addon ships two
 * separate .so files (CORE process module, HTTP module). nginx dlopen()s each
 * without RTLD_GLOBAL, so the CORE module cannot resolve a symbol defined in
 * the HTTP module. The accessor is therefore compiled INTO the CORE module and
 * reads the HTTP main conf out of the shared cycle; both TUs must agree on the
 * struct layout, which lives here.
 */

#ifndef _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_
#define _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef enum {
    NGX_HTTP_AUTOCERT_KEY_P256 = 0,
    NGX_HTTP_AUTOCERT_KEY_P384
} ngx_http_autocert_key_type_e;

typedef enum {
    NGX_HTTP_AUTOCERT_STORE_SECURE = 0,
    NGX_HTTP_AUTOCERT_STORE_CERTBOT
} ngx_http_autocert_store_e;

typedef enum {
    NGX_HTTP_AUTOCERT_CHALLENGE_HTTP_01 = 0,
    NGX_HTTP_AUTOCERT_CHALLENGE_TLS_ALPN_01,
    NGX_HTTP_AUTOCERT_CHALLENGE_DNS_01
} ngx_http_autocert_challenge_e;


/*
 * multi-CA M1 (#15 residual): the CA-identifying knobs grouped into one struct
 * so they live per-server (autocert_ca / _staging / _ca_certificate / _eab_kid /
 * _eab_hmac_key). M4 gives srv_conf its own ca_conf and merges global→server;
 * M2 groups names by effective CA into main_conf.ca_list; M5's driver iterates
 * ca_list and drives one ACME engine per CA from each entry's ca_conf.
 */
typedef struct {
    ngx_str_t    ca;                /* ACME directory URL */
    ngx_flag_t   staging;           /* autocert_staging on|off */
    ngx_str_t    ca_certificate;    /* PEM trust bundle to verify the CA, "" */
    ngx_str_t    eab_kid;           /* EAB key id (RFC 8555 §7.3.4), "" */
    ngx_str_t    eab_hmac_key;      /* base64url EAB HMAC key, "" */
} ngx_autocert_ca_conf_t;


/*
 * multi-CA M2: one entry per distinct CA the instance issues against. Built at
 * postconfig by grouping enabled server_names by their effective CA. In the M1/M2
 * world (directives still http{}-global) there is exactly ONE entry holding every
 * name; M4 (SRV-scope) makes per-vhost CAs produce several. ca_hash is crc32 of
 * the canonical CA URL as 8 lowercase hex + NUL, used by M3 for the per-CA
 * account dir (<path>/accounts/<hash>/account.key). account_key_path is filled
 * by M3; "" in M2.
 */
typedef struct {
    ngx_autocert_ca_conf_t  ca_conf;          /* resolved CA config */
    ngx_array_t            *names;             /* ngx_str_t under this CA */
    u_char                  ca_hash[9];        /* crc32(ca url) hex8 + NUL */
    ngx_str_t               account_key_path;  /* M3 fills; "" in M2 */
    /*
     * Per-CA account contact. Each CA has its own ACME account, so each gets its
     * own newAccount contact: the FIRST enabled vhost in this CA group with a
     * non-empty `autocert on <email>` supplies it; a second vhost in the same
     * group with a DIFFERENT non-empty email is rejected at postconfig (one CA =
     * one account = one contact). "" if no vhost in the group set an email.
     */
    ngx_str_t               email;
} ngx_autocert_ca_entry_t;


/* Per-server config: the on/off switch + optional contact (M0). */
typedef struct {
    ngx_flag_t   enable;    /* autocert on|off; NGX_CONF_UNSET until set */
    ngx_str_t    email;     /* optional ACME account contact, "" if absent */

    /* M4: per-server CA knobs. The CA directives are MAIN+SRV scope and write
     * here via SRV_CONF_OFFSET; merge_srv_conf folds the http{} default into
     * each server, postconfig resolves + validates each effective ca_conf and
     * groups names by CA URL into main_conf.ca_list. staging starts UNSET (set
     * in create_srv_conf) so merge can tell "not set" from "off". */
    ngx_autocert_ca_conf_t  ca_conf;
} ngx_http_autocert_srv_conf_t;


/*
 * Main (http{}-global) config: the autocert_* tuning knobs plus the shared
 * zone handle and the collected name set. Populated once, in the http{}
 * occurrence of create_main_conf, read by every server.
 */
typedef struct {
    ngx_str_t    email;             /* account contact (1st enabled vhost), "" */
    time_t       renew_before;      /* seconds before notAfter to renew */
    ngx_uint_t   key_type;          /* ngx_http_autocert_key_type_e */
    ngx_uint_t   store;             /* ngx_http_autocert_store_e */
    ngx_str_t    path;              /* cert store directory */
    ngx_uint_t   challenge;         /* ngx_http_autocert_challenge_e */

    /* M4b outbound-client knobs, read by the helper process. */
    ngx_resolver_t  *resolver;      /* built at config time, NULL if unset */
    time_t       resolver_timeout;  /* seconds */

    /* M16: dns-01 challenge. The driver publishes a TXT record by exec'ing an
     * operator hook (D3), waits dns_propagation_delay, then asks the CA to
     * validate. Hooks "" until set; delay defaults at init_main_conf. */
    ngx_str_t    dns_hook_add;      /* exec to publish the TXT, "" if unset */
    ngx_str_t    dns_hook_remove;   /* exec to remove the TXT, "" if unset */
    time_t       dns_propagation_delay;  /* seconds to wait after publish */
    time_t       dns_hook_timeout;  /* seconds to wait for a hook exec */

    ngx_shm_zone_t  *shm_zone;      /* published enabled-name set (for M4) */
    ngx_array_t     *names;         /* ngx_str_t, collected at postconfig */

    /* M2: enabled names grouped by CA. ngx_autocert_ca_entry_t array; one entry
     * until M4 introduces per-vhost CAs. The flat `names` above stays the serve
     * gate; ca_list is what the driver (M5) iterates to order per CA. */
    ngx_array_t     *ca_list;       /* ngx_autocert_ca_entry_t */

    /* M5 HTTP-01 challenge token store (token -> keyauth), written by the
     * helper, read by the :80 worker handler. */
    ngx_shm_zone_t  *challenge_zone;

    /* M5 test-only seed: autocert_test_challenge <token> <keyauth>; the helper
     * inserts it at startup so the serve path can be exercised without a full
     * order flow. token.len == 0 when unset. */
    ngx_str_t        test_token;
    ngx_str_t        test_keyauth;

    /* M10b tls-alpn-01 challenge cert store (domain -> {cert,key} PEM), written
     * by the helper, read by the worker handshake (cert_cb). */
    ngx_shm_zone_t  *alpn_zone;

    /* M10b test-only seed: autocert_test_alpn <domain> <keyauth>; the helper
     * builds the challenge cert at startup and inserts it into alpn_zone so the
     * ALPN serve path can be exercised without a full order flow. domain.len ==
     * 0 when unset. */
    ngx_str_t        test_alpn_domain;
    ngx_str_t        test_alpn_keyauth;
} ngx_http_autocert_main_conf_t;


/* The HTTP module instance, referenced by the accessor for its ctx_index. */
extern ngx_module_t  ngx_http_autocert_module;


/*
 * D4 wildcard (#16): map an issuable name to its on-disk store segment. A
 * wildcard name "*.example.com" is not a legal path segment (the leading "*"),
 * so it is stored under "_wildcard_.example.com"; every other name maps to
 * itself. Writes into buf (cap bytes incl. no NUL) and returns the written
 * length, or 0 if it would not fit. Shared by the driver freshness check, the
 * order store writer, and the serve cache key so all three agree on the dir.
 *
 * static ngx_inline in the shared header: each TU that uses it gets its own
 * copy, and TUs that include the header without using it don't warn under
 * -Werror (inline suppresses the unused-function diagnostic).
 */
#define NGX_AUTOCERT_WILDCARD_SEG  "_wildcard_."

/* Upper bound for a mapped store segment: a 253-char name minus "*." plus the
 * "_wildcard_." prefix, rounded up. Sizes the stack buffers callers pass in. */
#define NGX_AUTOCERT_DOMAIN_SEG_MAX  288

static ngx_inline size_t
ngx_autocert_fs_segment(u_char *buf, size_t cap, ngx_str_t *name)
{
    u_char  *p;
    size_t   rest, need;

    if (name->len >= 2 && name->data[0] == '*' && name->data[1] == '.') {
        rest = name->len - 2;                         /* after the "*." */
        need = sizeof(NGX_AUTOCERT_WILDCARD_SEG) - 1 + rest;
        if (need > cap) {
            return 0;
        }
        p = ngx_cpymem(buf, NGX_AUTOCERT_WILDCARD_SEG,
                       sizeof(NGX_AUTOCERT_WILDCARD_SEG) - 1);
        ngx_memcpy(p, name->data + 2, rest);
        return need;
    }

    if (name->len > cap) {
        return 0;
    }
    ngx_memcpy(buf, name->data, name->len);
    return name->len;
}


#endif /* _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_ */
