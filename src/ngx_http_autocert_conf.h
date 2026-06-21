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


/* Per-server config: the on/off switch + optional contact (M0). */
typedef struct {
    ngx_flag_t   enable;    /* autocert on|off; NGX_CONF_UNSET until set */
    ngx_str_t    email;     /* optional ACME account contact, "" if absent */
} ngx_http_autocert_srv_conf_t;


/*
 * Main (http{}-global) config: the autocert_* tuning knobs plus the shared
 * zone handle and the collected name set. Populated once, in the http{}
 * occurrence of create_main_conf, read by every server.
 */
typedef struct {
    ngx_str_t    ca;                /* ACME directory URL */
    ngx_flag_t   staging;          /* autocert_staging on|off */
    time_t       renew_before;      /* seconds before notAfter to renew */
    ngx_uint_t   key_type;          /* ngx_http_autocert_key_type_e */
    ngx_uint_t   store;             /* ngx_http_autocert_store_e */
    ngx_str_t    path;              /* cert store directory */
    ngx_uint_t   challenge;         /* ngx_http_autocert_challenge_e */

    /* M4b outbound-client knobs, read by the helper process. */
    ngx_resolver_t  *resolver;      /* built at config time, NULL if unset */
    time_t       resolver_timeout;  /* seconds */
    ngx_str_t    ca_certificate;    /* PEM trust bundle to verify the CA, "" */

    /* M15: External Account Binding (RFC 8555 §7.3.4). Both-or-neither; "" if
     * unset. eab_hmac_key is the base64url-encoded HMAC key as handed out by
     * the CA (decoded to raw bytes at registration time). */
    ngx_str_t    eab_kid;           /* CA-issued key identifier, "" if unset */
    ngx_str_t    eab_hmac_key;      /* base64url HMAC key, "" if unset */

    /* M16: dns-01 challenge. The driver publishes a TXT record by exec'ing an
     * operator hook (D3), waits dns_propagation_delay, then asks the CA to
     * validate. Hooks "" until set; delay defaults at init_main_conf. */
    ngx_str_t    dns_hook_add;      /* exec to publish the TXT, "" if unset */
    ngx_str_t    dns_hook_remove;   /* exec to remove the TXT, "" if unset */
    time_t       dns_propagation_delay;  /* seconds to wait after publish */

    ngx_shm_zone_t  *shm_zone;      /* published enabled-name set (for M4) */
    ngx_array_t     *names;         /* ngx_str_t, collected at postconfig */

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


#endif /* _NGX_HTTP_AUTOCERT_CONF_H_INCLUDED_ */
