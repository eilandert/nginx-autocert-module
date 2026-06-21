/*
 * ngx_autocert_shared — the narrow interface the CORE helper process uses to
 * read the HTTP module's configuration without depending on the HTTP module's
 * private conf struct. The helper is an NGX_CORE_MODULE; it cannot use
 * ngx_http_conf_get_module_main_conf, and the autocert main-conf struct is
 * file-private to ngx_http_autocert_module.c. So the HTTP module exports one
 * accessor that copies the few fields the helper needs into this flat struct.
 */

#ifndef _NGX_AUTOCERT_SHARED_H_INCLUDED_
#define _NGX_AUTOCERT_SHARED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct {
    ngx_uint_t       configured;     /* 0 => autocert not present in http{} */
    ngx_str_t        ca;             /* ACME directory URL */
    ngx_resolver_t  *resolver;       /* may be NULL if autocert_resolver unset */
    time_t           resolver_timeout;
    ngx_str_t        ca_certificate; /* PEM trust bundle path, "" => system */
    ngx_str_t        eab_kid;        /* EAB key id (RFC 8555 §7.3.4), "" */
    ngx_str_t        eab_hmac_key;   /* base64url EAB HMAC key, "" */
    ngx_str_t        dns_hook_add;     /* M16 dns-01 publish-TXT exec, "" */
    ngx_str_t        dns_hook_remove;  /* M16 dns-01 remove-TXT exec, "" */
    time_t           dns_propagation_delay;  /* M16 seconds after publish */
    time_t           dns_hook_timeout;  /* M16 seconds to wait for a hook exec */
    ngx_uint_t       key_type;       /* ngx_http_autocert_key_type_e (acct key) */
    ngx_uint_t       store;          /* ngx_http_autocert_store_e (disk layout) */
    ngx_str_t        path;           /* cert store dir (holds the account key) */
    time_t           renew_before;   /* M8: seconds before notAfter to renew */
    ngx_uint_t       challenge;      /* M10c: ngx_http_autocert_challenge_e */

    /* M5: the challenge token store the helper writes (NULL if not set up). */
    ngx_shm_zone_t  *challenge_zone;
    /* M6a: the collected enabled server names (ngx_str_t array, NULL/empty if
     * none). The order flow issues for the first name for now; multi-name
     * iteration is later (M6+). Points into the HTTP main-conf pool, which
     * outlives the helper run. */
    ngx_array_t     *names;
    /* M5 test seed (token.len == 0 when unset). */
    ngx_str_t        test_token;
    ngx_str_t        test_keyauth;

    /* M10b: the tls-alpn-01 challenge cert store the helper writes (NULL if not
     * set up). */
    ngx_shm_zone_t  *alpn_zone;
    /* M10b test seed (domain.len == 0 when unset). */
    ngx_str_t        test_alpn_domain;
    ngx_str_t        test_alpn_keyauth;
} ngx_autocert_conf_t;


/*
 * Fill *out from the running cycle's HTTP autocert main conf. Returns NGX_OK
 * with out->configured set appropriately (0 if the http{} block has no
 * autocert main conf, e.g. no http{} at all), NGX_ERROR only on a NULL out.
 * Safe to call from the helper (CORE) process against its own cycle.
 */
ngx_int_t ngx_autocert_get_conf(ngx_cycle_t *cycle, ngx_autocert_conf_t *out);


#endif /* _NGX_AUTOCERT_SHARED_H_INCLUDED_ */
