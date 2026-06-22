/*
 * ngx_http_autocert_module — automatic ACME certificate provisioning.
 *
 * M0: module skeleton plus `autocert on|off [email];` (http{} global or
 *     server{} per-vhost; per-vhost overrides global).
 * M2: the global tuning directives (`autocert_ca`, `autocert_renew_before`,
 *     `autocert_key_type`, `autocert_store`, `autocert_path`,
 *     `autocert_challenge`) and the config-model walk that, at the end of
 *     configuration, collects the server_name set of every autocert-enabled
 *     vhost into a shared-memory zone. That zone is the seed the ACME helper
 *     process (M4) will consume; no ACME logic runs yet.
 *
 * Builds and loads on both nginx and angie.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_ssl_module.h>
#include <openssl/sha.h>           /* SHA256() for the per-CA account-dir hash */

#include "ngx_http_autocert_conf.h"
#include "ngx_autocert_challenge.h"
#include "ngx_autocert_alpn.h"
#include "ngx_autocert_serve.h"
#include "ngx_autocert_driver.h"


#define NGX_HTTP_AUTOCERT_DEFAULT_CA \
    "https://acme-v02.api.letsencrypt.org/directory"

#define NGX_HTTP_AUTOCERT_STAGING_CA \
    "https://acme-staging-v02.api.letsencrypt.org/directory"

#define NGX_HTTP_AUTOCERT_WK_PREFIX  "/.well-known/acme-challenge/"

/* Challenge token store zone: small; one node per in-flight authorization. */
#define NGX_HTTP_AUTOCERT_CHALLENGE_ZONE_SIZE  (128 * 1024)

/* tls-alpn-01 challenge-cert store zone (M10b): a cert+key PEM per in-flight
 * authorization — larger entries than the token store, still few of them. */
#define NGX_HTTP_AUTOCERT_ALPN_ZONE_SIZE  (256 * 1024)

/* Default zone size: enough for a few thousand names; admin-tunable later. */
#define NGX_HTTP_AUTOCERT_ZONE_SIZE  (256 * 1024)


/* Config struct + enum defs are shared via ngx_http_autocert_conf.h so the
 * CORE helper's accessor TU agrees on the layout. */


/* Shared-zone payload: a flat list of NUL-free name strings in slab memory. */
typedef struct {
    ngx_uint_t   nelts;
    ngx_str_t    elts[1];           /* nelts entries; data also in slab */
} ngx_http_autocert_sh_t;


static void *ngx_http_autocert_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_autocert_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_autocert_create_srv_conf(ngx_conf_t *cf);
static char *ngx_http_autocert_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static ngx_int_t ngx_http_autocert_postconfig(ngx_conf_t *cf);
static ngx_int_t ngx_http_autocert_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);
static ngx_int_t ngx_http_autocert_challenge_handler(ngx_http_request_t *r);
#if (NGX_AUTOCERT_TEST)
static char *ngx_http_autocert_test_challenge(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_http_autocert_test_alpn(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
#endif

static char *ngx_http_autocert(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_autocert_contact(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_key_type(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_challenge(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_wildcard(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/* D5 (#16) autocert_wildcard helpers. */
static ngx_int_t ngx_http_autocert_is_wildcard(ngx_str_t *name);
static ngx_int_t ngx_http_autocert_name_covered(ngx_str_t *name,
    ngx_array_t *wildcards);
static ngx_int_t ngx_http_autocert_add_name(ngx_conf_t *cf,
    ngx_http_autocert_main_conf_t *amcf, ngx_autocert_ca_conf_t *cac,
    ngx_http_autocert_srv_conf_t *ascf, ngx_str_t name);


static ngx_command_t  ngx_http_autocert_commands[] = {

    /*
     * Valid in http{} and server{}. gzip-style: a single SRV-level conf with
     * SRV_CONF_OFFSET; the http{} occurrence writes the main-level srv_conf
     * slot, which ngx_http_merge_servers() then folds into every server,
     * giving a global default plus per-vhost override.
     */
    { ngx_string("autocert"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_autocert,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    /* ACME account contact email (was the optional 2nd arg of `autocert on`;
     * split out for clarity so `autocert on|off` is a plain switch). MAIN+SRV,
     * per-CA: the first non-empty contact in a CA group supplies that CA's
     * newAccount email (same resolution as before). */
    { ngx_string("autocert_contact"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_http_autocert_contact,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    /*
     * M4 (per-vhost multi-CA, #15): the CA-identifying knobs are MAIN+SRV
     * scope. The http{} occurrence sets the instance-wide default (written into
     * the main-level srv_conf via SRV_CONF_OFFSET); a server{} occurrence
     * overrides it for that vhost. merge_srv_conf folds default->server, then
     * postconfig resolves+validates each server's effective ca_conf and groups
     * names by CA into ca_list. (Other tuning knobs below stay http{}-global —
     * one ACME policy.)
     */

    { ngx_string("autocert_ca"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_autocert_srv_conf_t, ca_conf.ca),
      NULL },

    /* Shorthand for the LE staging directory URL; mutually exclusive with
     * autocert_ca. Use in CI/CD to exercise the full issuance flow without
     * consuming production rate limits. */
    { ngx_string("autocert_staging"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_autocert_srv_conf_t, ca_conf.staging),
      NULL },

    /*
     * D5 (#16): declare wildcard SAN(s) for this scope without putting a
     * wildcard in server_name (which would also make the vhost a subdomain
     * catch-all). MAIN+SRV: http{} sets an instance-wide wildcard inherited by
     * every vhost; a server{} occurrence appends its own. Repeatable / 1+ args.
     * dns-01 only (enforced at postconfig). A concrete server_name covered by a
     * declared wildcard is served from the wildcard cert, not issued separately.
     */
    { ngx_string("autocert_wildcard"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_autocert_wildcard,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("autocert_renew_before"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, renew_before),
      NULL },

    { ngx_string("autocert_key_type"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_autocert_key_type,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("autocert_store_layout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_autocert_store,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("autocert_store_path"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, path),
      NULL },

    { ngx_string("autocert_challenge"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_autocert_challenge,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* M4b: outbound ACME client transport knobs (http{}-global). */

    { ngx_string("autocert_resolver"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      ngx_http_autocert_resolver,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("autocert_resolver_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, resolver_timeout),
      NULL },

    { ngx_string("autocert_ca_trusted_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_autocert_srv_conf_t, ca_conf.ca_certificate),
      NULL },

    /* M15: External Account Binding (RFC 8555 §7.3.4) for commercial CAs
     * (ZeroSSL, Sectigo, Google) that gate newAccount behind a CA-issued
     * key-id + HMAC key. Both-or-neither — enforced in init_main_conf. */

    { ngx_string("autocert_eab_kid"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_autocert_srv_conf_t, ca_conf.eab_kid),
      NULL },

    { ngx_string("autocert_eab_hmac_key"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_http_autocert_srv_conf_t, ca_conf.eab_hmac_key),
      NULL },

    /* M16: dns-01 operator exec hooks (D3). Both required when
     * autocert_challenge dns-01 (enforced in init_main_conf). Each is run
     * fork+execve with argv {hook, _acme-challenge.<domain>, <txt>} to publish
     * (add) / remove the TXT record. Paths must be absolute. http{}-global. */

    { ngx_string("autocert_dns_hook_add"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, dns_hook_add),
      NULL },

    { ngx_string("autocert_dns_hook_remove"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, dns_hook_remove),
      NULL },

    { ngx_string("autocert_dns_propagation_delay"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, dns_propagation_delay),
      NULL },

    { ngx_string("autocert_dns_hook_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_sec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, dns_hook_timeout),
      NULL },

#if (NGX_AUTOCERT_TEST)
    /* TEST-ONLY: seed one token->keyauth into the challenge store at startup so
     * the HTTP-01 serve path can be tested before the order flow (M6) exists.
     * Compiled in ONLY under -DNGX_AUTOCERT_TEST (CI); never in a production
     * build, so a stray directive cannot seed a forged key authorization. */
    { ngx_string("autocert_test_challenge"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_autocert_test_challenge,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    /* TEST-ONLY: seed one domain's tls-alpn-01 challenge cert into the ALPN
     * store at startup (M10b) so the ALPN serve path can be tested before the
     * order wiring (M10c) exists. Compiled in ONLY under -DNGX_AUTOCERT_TEST. */
    { ngx_string("autocert_test_alpn"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_autocert_test_alpn,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },
#endif

      ngx_null_command
};


/*
 * Worker-0 ACME driver gate. The ACME engine must run in exactly ONE process,
 * so arm it only on worker 0 of a normal (master+workers) run, or in the single
 * process of `master_process off`. ngx_worker is the 0-based worker index; the
 * NGX_PROCESS_SINGLE case (single-process mode) has ngx_worker == 0 too, so the
 * single gate covers both. Other workers (and the master / cache procs / signaller)
 * return without arming — they only serve challenges from the shared zone.
 */
/*
 * Single-process (`master_process off`) reload tracker. In single-process mode
 * the process survives a SIGHUP and nginx re-runs every module's init_module
 * (with the new cycle) but NEVER calls exit_process/init_process again. We use
 * init_module as the reload hook there: the FIRST init_module is the initial
 * boot (init_process still does the arming), every later one is a reload and must
 * rebind the driver + serve state to the new cycle. The flag is set in
 * init_process so init_module can tell boot from reload. Irrelevant in
 * master+workers mode (init_module runs in the master, which holds no per-worker
 * driver/serve state; fresh workers re-init via fork each generation).
 */
static ngx_uint_t  ngx_http_autocert_single_started;


static ngx_int_t
ngx_http_autocert_init_module(ngx_cycle_t *cycle)
{
    if (ngx_process == NGX_PROCESS_SINGLE
        && ngx_worker == 0
        && ngx_http_autocert_single_started)
    {
        /* A reload in `master_process off`: rebuild against the new cycle. */
        ngx_autocert_serve_reload();
        ngx_autocert_driver_reload(cycle);
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_autocert_init_process(ngx_cycle_t *cycle)
{
    if ((ngx_process == NGX_PROCESS_WORKER
         || ngx_process == NGX_PROCESS_SINGLE)
        && ngx_worker == 0)
    {
        if (ngx_process == NGX_PROCESS_SINGLE) {
            ngx_http_autocert_single_started = 1;
        }
        ngx_autocert_driver_init_process(cycle);
    }

    return NGX_OK;
}


static void
ngx_http_autocert_exit_process(ngx_cycle_t *cycle)
{
    if ((ngx_process == NGX_PROCESS_WORKER
         || ngx_process == NGX_PROCESS_SINGLE)
        && ngx_worker == 0)
    {
        ngx_autocert_driver_exit_process(cycle);
    }
}


static ngx_http_module_t  ngx_http_autocert_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_autocert_postconfig,          /* postconfiguration */

    ngx_http_autocert_create_main_conf,    /* create main configuration */
    ngx_http_autocert_init_main_conf,      /* init main configuration */

    ngx_http_autocert_create_srv_conf,     /* create server configuration */
    ngx_http_autocert_merge_srv_conf,      /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
};


ngx_module_t  ngx_http_autocert_module = {
    NGX_MODULE_V1,
    &ngx_http_autocert_module_ctx,     /* module context */
    ngx_http_autocert_commands,        /* module directives */
    NGX_HTTP_MODULE,                   /* module type */
    NULL,                              /* init master */
    ngx_http_autocert_init_module,     /* init module (single-process reload hook) */
    ngx_http_autocert_init_process,    /* init process (arms ACME on worker 0) */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    ngx_http_autocert_exit_process,    /* exit process (tears ACME down) */
    NULL,                              /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_http_autocert_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_autocert_main_conf_t  *amcf;

    amcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_autocert_main_conf_t));
    if (amcf == NULL) {
        return NULL;
    }

    /* path zeroed by pcalloc; set in init_main_conf. The CA knobs are SRV scope
     * (srv_conf.ca_conf); postconfig groups names by effective CA into ca_list,
     * which the worker-0 driver iterates per CA (M5). No flat amcf->ca_conf. */
    amcf->renew_before = NGX_CONF_UNSET;
    amcf->key_type = NGX_CONF_UNSET_UINT;
    amcf->store = NGX_CONF_UNSET_UINT;
    amcf->challenge = NGX_CONF_UNSET_UINT;

    /* resolver pointer + ca_certificate zeroed by pcalloc */
    amcf->resolver_timeout = NGX_CONF_UNSET;

    /* dns_hook_add/remove zeroed by pcalloc; delay+timeout defaulted in init. */
    amcf->dns_propagation_delay = NGX_CONF_UNSET;
    amcf->dns_hook_timeout = NGX_CONF_UNSET;

    return amcf;
}


static char *
ngx_http_autocert_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;

    /*
     * M4: the CA knobs (ca/staging/ca_certificate/eab_*) are now MAIN+SRV
     * scope and live in srv_conf.ca_conf. Their defaulting + validation
     * (staging<->ca exclusion, default CA, ca_certificate abspath, EAB
     * both-or-neither) moved to ngx_http_autocert_resolve_ca_conf(), run
     * per effective server ca_conf in postconfig. init_main_conf keeps only
     * the genuinely instance-wide knobs below.
     */

    /* User spec: 7d default (industry-safer 30d noted but honoring request). */
    ngx_conf_init_value(amcf->renew_before, 7 * 24 * 60 * 60);

    ngx_conf_init_uint_value(amcf->key_type, NGX_HTTP_AUTOCERT_KEY_P384);
    ngx_conf_init_uint_value(amcf->store, NGX_HTTP_AUTOCERT_STORE_SECURE);
    ngx_conf_init_uint_value(amcf->challenge,
                             NGX_HTTP_AUTOCERT_CHALLENGE_HTTP_01);

    if (amcf->path.data == NULL) {
        ngx_str_set(&amcf->path, "autocert");
    }

    /*
     * M7: make the store path absolute relative to the nginx prefix, NOT the
     * process CWD. The helper (account.key) and the serve path (cert store)
     * both read it; the helper's CWD is undefined, so a relative path would
     * resolve differently between config-time and the helper. ngx_conf_full_name
     * prepends the prefix when the path is not already absolute. (Folds the M6b
     * residual.)
     */
    if (ngx_conf_full_name(cf->cycle, &amcf->path, 1) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    ngx_conf_init_value(amcf->resolver_timeout, 30);
    ngx_conf_init_value(amcf->dns_propagation_delay, 10);   /* M16 dns-01 */
    ngx_conf_init_value(amcf->dns_hook_timeout, 30);        /* M16 hook exec */

    /*
     * A non-positive dns_hook_timeout reaches the driver as 0, which makes the
     * wait loop SIGKILL the hook on the first poll tick — silently breaking ALL
     * dns-01 issuance. Reject it at config time rather than fail mysteriously at
     * runtime. (resolver_timeout / dns_propagation_delay tolerate 0 = "no wait",
     * but a 0 hook timeout is never meaningful.)
     */
    if (amcf->dns_hook_timeout <= 0) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "autocert_dns_hook_timeout must be greater than 0");
        return NGX_CONF_ERROR;
    }

    /*
     * M16 dns-01: the publish/remove hooks are exec'd by the driver. A hook
     * path must be absolute — the driver's CWD is undefined, so a relative path
     * would resolve unpredictably (mirrors the autocert_path reasoning above).
     * Reject a given-but-empty value too.
     */
    if (amcf->dns_hook_add.data != NULL
        && (amcf->dns_hook_add.len == 0 || amcf->dns_hook_add.data[0] != '/'))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"autocert_dns_hook_add\" must be a non-empty absolute path");
        return NGX_CONF_ERROR;
    }
    if (amcf->dns_hook_remove.data != NULL
        && (amcf->dns_hook_remove.len == 0
            || amcf->dns_hook_remove.data[0] != '/'))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"autocert_dns_hook_remove\" must be a non-empty absolute path");
        return NGX_CONF_ERROR;
    }

    /*
     * When dns-01 is the active challenge, both hooks are mandatory: without
     * them the driver computes a TXT value it cannot publish, so every order
     * would stall at the propagation wait and then fail validation. Fail fast
     * at config rather than at first issuance.
     */
    if (amcf->challenge == NGX_HTTP_AUTOCERT_CHALLENGE_DNS_01
        && (amcf->dns_hook_add.data == NULL
            || amcf->dns_hook_remove.data == NULL))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"autocert_challenge dns-01\" requires both "
            "\"autocert_dns_hook_add\" and \"autocert_dns_hook_remove\"");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static void *
ngx_http_autocert_create_srv_conf(ngx_conf_t *cf)
{
    ngx_http_autocert_srv_conf_t  *ascf;

    ascf = ngx_pcalloc(cf->pool, sizeof(ngx_http_autocert_srv_conf_t));
    if (ascf == NULL) {
        return NULL;
    }

    /* ascf->email is zeroed by pcalloc */
    ascf->enable = NGX_CONF_UNSET;

    /* M1 prep: per-server CA knobs unset until M4 wires SRV-scope directives +
     * merge. ca_conf str fields are zeroed by pcalloc (= unset); only the flag
     * needs an explicit UNSET so a future merge_value can detect "not set". */
    ascf->ca_conf.staging = NGX_CONF_UNSET;

    /* D5: UNSET_PTR so merge can tell "no autocert_wildcard here" from "empty". */
    ascf->wildcards = NGX_CONF_UNSET_PTR;

    return ascf;
}


static char *
ngx_http_autocert_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_autocert_srv_conf_t  *prev = parent;
    ngx_http_autocert_srv_conf_t  *conf = child;

    /* A server{} setting overrides the http{} global; otherwise inherit. */
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->email, prev->email, "");

    /*
     * M4 CA-config inheritance. The CA selector is the pair {autocert_ca,
     * autocert_staging}; the ancillary knobs (ca_certificate trust bundle, EAB
     * key-id + HMAC) are CA-BOUND credentials/roots.
     *
     * Rule 1 (selector is a unit): a server that explicitly sets EITHER ca or
     * staging fully owns the selector and inherits NEITHER from the http{}
     * default — so `server { autocert_staging on; }` overrides a global
     * `autocert_ca` cleanly instead of inheriting it and then tripping the
     * staging<->ca mutual-exclusion check (Codex M4 #1).
     *
     * Rule 2 (don't leak CA-bound creds across CAs): the trust bundle + EAB
     * credentials inherit from the global ONLY when the server did NOT switch
     * CAs. A server that overrides the CA but leaves EAB/trust unset gets none —
     * inheriting CA-A's EAB key or pinned root for CA-B would send the wrong
     * credentials / pin the wrong root (Codex M4 #2). Such a server must set
     * them explicitly.
     *
     * Strings use a raw data==NULL inherit (NOT ngx_conf_merge_str_value) so the
     * "unset" signal survives into postconfig's resolve step.
     */
    {
        ngx_flag_t  inherit_selector;

        /* staging starts NGX_CONF_UNSET (create_srv_conf); ca starts NULL. */
        inherit_selector = (conf->ca_conf.ca.data == NULL
                            && conf->ca_conf.staging == NGX_CONF_UNSET);

        if (inherit_selector) {
            conf->ca_conf.ca = prev->ca_conf.ca;
            conf->ca_conf.staging = prev->ca_conf.staging;
        }
        ngx_conf_init_value(conf->ca_conf.staging, 0);

        if (inherit_selector) {
            if (conf->ca_conf.ca_certificate.data == NULL) {
                conf->ca_conf.ca_certificate = prev->ca_conf.ca_certificate;
            }
            if (conf->ca_conf.eab_kid.data == NULL) {
                conf->ca_conf.eab_kid = prev->ca_conf.eab_kid;
            }
            if (conf->ca_conf.eab_hmac_key.data == NULL) {
                conf->ca_conf.eab_hmac_key = prev->ca_conf.eab_hmac_key;
            }
        }
    }

    /*
     * D5 wildcard inheritance: http{}-level autocert_wildcard is inherited by
     * every vhost; a server{} that declares its own gets the http{} set too
     * (concatenated). A server with none simply inherits the http{} pointer
     * (read-only). Duplicates across the two scopes are harmless — postconfig
     * dedups by name when adding to the issuance set.
     */
    if (conf->wildcards == NGX_CONF_UNSET_PTR) {
        conf->wildcards = prev->wildcards;

    } else if (prev->wildcards != NGX_CONF_UNSET_PTR) {
        ngx_str_t   *pw = prev->wildcards->elts;
        ngx_str_t   *w;
        ngx_uint_t   i;

        for (i = 0; i < prev->wildcards->nelts; i++) {
            w = ngx_array_push(conf->wildcards);
            if (w == NULL) {
                return NGX_CONF_ERROR;
            }
            *w = pw[i];
        }
    }

    return NGX_CONF_OK;
}


/*
 * M4: default + validate one server's effective CA config, in place. Mirrors
 * the logic that lived in init_main_conf when the CA knobs were http{}-global:
 * staging<->ca mutual exclusion, default/staging CA URL, ca_certificate made
 * absolute (the worker-0 driver loads it with a plain OpenSSL call from an
 * undefined CWD), and EAB key-id<->HMAC both-or-neither. Run per distinct
 * effective server ca_conf in postconfig, before grouping names by CA URL.
 */
static ngx_int_t
ngx_http_autocert_resolve_ca_conf(ngx_conf_t *cf, ngx_autocert_ca_conf_t *cac)
{
    if (cac->staging) {
        if (cac->ca.data != NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "\"autocert_staging\" and \"autocert_ca\" are mutually "
                "exclusive");
            return NGX_ERROR;
        }
        ngx_str_set(&cac->ca, NGX_HTTP_AUTOCERT_STAGING_CA);

    } else if (cac->ca.data == NULL) {
        ngx_str_set(&cac->ca, NGX_HTTP_AUTOCERT_DEFAULT_CA);
    }

    if (cac->ca_certificate.len != 0
        && ngx_conf_full_name(cf->cycle, &cac->ca_certificate, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* EAB: a key-id without an HMAC key (or vice versa) is meaningless and
     * would silently fall back to an unbound newAccount the CA rejects, so
     * fail config rather than surprise the operator at registration time.
     * Presence is "directive given" (data != NULL after str_slot); an explicit
     * empty value ("") is given-but-useless and must also fail. */
    if ((cac->eab_kid.data != NULL) != (cac->eab_hmac_key.data != NULL)
        || (cac->eab_kid.data != NULL
            && (cac->eab_kid.len == 0 || cac->eab_hmac_key.len == 0)))
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "\"autocert_eab_kid\" and \"autocert_eab_hmac_key\" must both be "
            "set (non-empty) or both absent");
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * M4: the CA a given server issues against — its own merged ca_conf. Each
 * server's ca_conf was folded from the http{} default in merge_srv_conf and
 * resolved (defaulted + validated) by the caller before this is used to key the
 * ca_list group. This is the single seam that turns one CA group into many:
 * servers with distinct effective CA URLs now land in distinct ca_list entries.
 */
static ngx_autocert_ca_conf_t *
ngx_http_autocert_effective_ca(ngx_http_autocert_main_conf_t *amcf,
    ngx_http_autocert_srv_conf_t *ascf)
{
    (void) amcf;
    return &ascf->ca_conf;
}


/*
 * M2: find (or create) the ca_list entry for a CA, keyed by its canonical
 * directory URL. ca_hash = SHA-256(url)[:8] as 16 lowercase hex, used by M3 for the
 * per-CA account dir. Returns NULL on alloc failure.
 */
static ngx_autocert_ca_entry_t *
ngx_http_autocert_ca_entry(ngx_conf_t *cf,
    ngx_http_autocert_main_conf_t *amcf, ngx_autocert_ca_conf_t *cac)
{
    static const u_char       hex[] = "0123456789abcdef";
    ngx_autocert_ca_entry_t  *e;
    ngx_uint_t                i;
    u_char                    md[SHA256_DIGEST_LENGTH];

    e = amcf->ca_list->elts;
    for (i = 0; i < amcf->ca_list->nelts; i++) {
        if (e[i].ca_conf.ca.len != cac->ca.len
            || ngx_strncmp(e[i].ca_conf.ca.data, cac->ca.data, cac->ca.len) != 0)
        {
            continue;
        }

        /*
         * Same CA URL => same ACME account (account dir is keyed on the URL
         * hash). The CA-bound ancillary knobs must therefore agree too: the
         * group resolves to ONE trust bundle + ONE EAB credential, and grouping
         * keys only on the URL, so two vhosts that name the same CA URL with a
         * different ca_certificate or different EAB would silently collapse and
         * the second config would be ignored (Codex M4 #3). Reject instead.
         */
        /*
         * Compare lengths first, and only ngx_strncmp() when the shared length
         * is non-zero: an absent trust bundle / EAB field has data == NULL, and
         * ngx_strncmp(NULL, NULL, 0) is undefined C (memcmp with NULL args),
         * even though glibc happens to tolerate it.
         */
        if (e[i].ca_conf.ca_certificate.len != cac->ca_certificate.len
            || (cac->ca_certificate.len != 0
                && ngx_strncmp(e[i].ca_conf.ca_certificate.data,
                               cac->ca_certificate.data,
                               cac->ca_certificate.len) != 0)
            || e[i].ca_conf.eab_kid.len != cac->eab_kid.len
            || (cac->eab_kid.len != 0
                && ngx_strncmp(e[i].ca_conf.eab_kid.data, cac->eab_kid.data,
                               cac->eab_kid.len) != 0)
            || e[i].ca_conf.eab_hmac_key.len != cac->eab_hmac_key.len
            || (cac->eab_hmac_key.len != 0
                && ngx_strncmp(e[i].ca_conf.eab_hmac_key.data,
                               cac->eab_hmac_key.data,
                               cac->eab_hmac_key.len) != 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "autocert: CA \"%V\" is configured with conflicting "
                "\"autocert_ca_trusted_certificate\" / \"autocert_eab_*\" across "
                "servers; one CA URL must use one trust bundle and one EAB "
                "credential", &cac->ca);
            return NULL;
        }

        return &e[i];
    }

    e = ngx_array_push(amcf->ca_list);
    if (e == NULL) {
        return NULL;
    }
    ngx_memzero(e, sizeof(ngx_autocert_ca_entry_t));
    e->ca_conf = *cac;
    e->names = ngx_array_create(cf->pool, 4, sizeof(ngx_str_t));
    if (e->names == NULL) {
        return NULL;
    }

    /*
     * Per-CA account-dir key: leading 64 bits of SHA-256(canonical CA URL),
     * 16 lowercase hex. crc32/hex8 was too short — two distinct CA URLs could
     * collide and then share one accounts/<hash>/account.key, breaking the
     * promised per-CA key isolation. 64 bits makes that collision infeasible.
     */
    if (SHA256(cac->ca.data, cac->ca.len, md) == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "autocert: SHA256() failed hashing CA URL \"%V\"",
                           &cac->ca);
        return NULL;
    }
    for (i = 0; i < NGX_AUTOCERT_CA_HASH_HEX / 2; i++) {
        e->ca_hash[2 * i]     = hex[md[i] >> 4];
        e->ca_hash[2 * i + 1] = hex[md[i] & 0xf];
    }
    e->ca_hash[NGX_AUTOCERT_CA_HASH_HEX] = '\0';

    /*
     * M3: per-CA account key path = <path>/accounts/<ca_hash>/account.key.
     * amcf->path is already absolute here (init_main_conf ran first). The driver
     * mkdir's the dirs + migrates the old flat <path>/account.key at runtime.
     */
    {
        u_char  *p;
        size_t   len;

        len = amcf->path.len + sizeof("/accounts/") - 1
              + NGX_AUTOCERT_CA_HASH_HEX + sizeof("/account.key") - 1;
        p = ngx_pnalloc(cf->pool, len + 1);
        if (p == NULL) {
            return NULL;
        }
        e->account_key_path.data = p;
        e->account_key_path.len = len;
        p = ngx_cpymem(p, amcf->path.data, amcf->path.len);
        p = ngx_cpymem(p, "/accounts/", sizeof("/accounts/") - 1);
        p = ngx_cpymem(p, e->ca_hash, NGX_AUTOCERT_CA_HASH_HEX);
        p = ngx_cpymem(p, "/account.key", sizeof("/account.key") - 1);
        *p = '\0';
    }

    return e;
}


/*
 * Bind a vhost's account contact to its CA group. First non-empty email in the
 * group wins (becomes the CA's newAccount contact); a second, DIFFERENT non-empty
 * email for the SAME CA is a config error — one CA has one account, so one
 * contact. An empty vhost email never overrides an already-set group contact.
 */
static ngx_int_t
ngx_http_autocert_bind_ca_email(ngx_conf_t *cf, ngx_autocert_ca_entry_t *ce,
    ngx_str_t *email)
{
    if (email->len == 0) {
        return NGX_OK;
    }

    if (ce->email.len == 0) {
        ce->email = *email;
        return NGX_OK;
    }

    if (ce->email.len != email->len
        || ngx_strncmp(ce->email.data, email->data, email->len) != 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "autocert: CA \"%V\" is configured with conflicting account "
            "contacts across servers (\"%V\" vs \"%V\"); one CA uses one "
            "account and one contact", &ce->ca_conf.ca, &ce->email, email);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Run after the whole http{} config is parsed and merged. Walk every server,
 * and for each one with autocert enabled, copy its server_name strings into
 * the main-conf name array (deduplicated) AND into its CA's ca_list group. Then
 * size and register the shared zone that publishes that set to the helper.
 */
/*
 * D5: autocert_wildcard setter. Validates each arg is a sole-leading-label
 * wildcard ("*.example.com") and accumulates them on the scope's srv_conf
 * (lazily creating the array), so repeated directives and the MAIN+SRV merge
 * both append. dns-01-only is checked at postconfig (challenge isn't known yet).
 */
static char *
ngx_http_autocert_wildcard(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_srv_conf_t  *ascf = conf;
    ngx_str_t                     *value = cf->args->elts;
    ngx_str_t                     *w;
    ngx_uint_t                      i;

    if (ascf->wildcards == NGX_CONF_UNSET_PTR) {
        ascf->wildcards = ngx_array_create(cf->pool, 2, sizeof(ngx_str_t));
        if (ascf->wildcards == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if (!ngx_http_autocert_is_wildcard(&value[i])) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "autocert_wildcard: \"%V\" is not a leading-label wildcard "
                "(expected the form \"*.example.com\")", &value[i]);
            return NGX_CONF_ERROR;
        }

        w = ngx_array_push(ascf->wildcards);
        if (w == NULL) {
            return NGX_CONF_ERROR;
        }

        /* Store a lowercased copy. DNS names are case-insensitive, the SNI is
         * lowercased before the serve-path lookup, and the wildcard's on-disk
         * "_wildcard_.<rest>" segment must agree with that lookup — so a
         * mixed-case "*.Example.com" has to be normalized here or the issued
         * cert would never be found at handshake time. */
        w->len = value[i].len;
        w->data = ngx_pnalloc(cf->pool, value[i].len);
        if (w->data == NULL) {
            return NGX_CONF_ERROR;
        }
        ngx_strlow(w->data, value[i].data, value[i].len);
    }

    return NGX_CONF_OK;
}


/* D5: a sole, leading-label wildcard "*.rest" (the only wildcard ACME issues).
 * Beyond the shape gate, reject a malformed "rest" — empty labels (".."), a
 * leading or trailing dot, or any other '*'. Without this, garbage like
 * "*..example.com" would pass config, suppress a concrete name, and only fail
 * later at issuance, leaving that name with no certificate. (Codex LOW.) */
static ngx_int_t
ngx_http_autocert_is_wildcard(ngx_str_t *name)
{
    u_char  *p, *end;

    if (name->len < 3 || name->data[0] != '*' || name->data[1] != '.') {
        return 0;
    }

    end = name->data + name->len;

    /* "rest" starts at data+2; must be a non-empty dotted name with no empty
     * label and no further '*'. data[1] is the separating '.', so the byte at
     * data+2 must not be another '.' (that would be a leading empty label). */
    if (name->data[2] == '.' || end[-1] == '.') {
        return 0;                                   /* leading/trailing empty label */
    }

    for (p = name->data + 2; p < end; p++) {
        if (*p == '*') {
            return 0;                               /* only the leading-label '*' */
        }
        if (*p == '.' && p[1] == '.') {
            return 0;                               /* consecutive dots = empty label */
        }
    }

    return 1;
}


/*
 * D5: is `name` a single-label subdomain of one of the wildcards? i.e. exactly
 * "<label>.<rest>" (one non-empty leading label, no embedded dot) where
 * "*.<rest>" is declared. Mirrors the RFC 6125 one-label fold the serve path
 * uses, so a name suppressed here is exactly one the wildcard cert will serve.
 * The apex (rest itself) and multi-label names are NOT covered.
 */
static ngx_int_t
ngx_http_autocert_name_covered(ngx_str_t *name, ngx_array_t *wildcards)
{
    ngx_str_t   *wc = wildcards->elts;
    ngx_uint_t   i;
    u_char      *dot;
    size_t       rest_len;
    u_char      *rest;

    /* A wildcard name is never "covered" by a wildcard — only concrete names
     * are suppressed. (Without this, "*.example.com" would match the wildcard
     * "*.example.com" via the rest-compare below and get routed through the
     * wrong path; a wildcard server_name must keep its own server_name flow.) */
    if (name->len != 0 && name->data[0] == '*') {
        return 0;
    }

    dot = ngx_strlchr(name->data, name->data + name->len, '.');
    if (dot == NULL || dot == name->data || dot + 1 >= name->data + name->len) {
        return 0;                       /* no label, empty label, or trailing dot */
    }

    rest = dot + 1;
    rest_len = (size_t) (name->data + name->len - rest);

    for (i = 0; i < wildcards->nelts; i++) {
        /* wc[i] is "*.X" (validated, lowercased); compare X to the part after
         * the 1st dot, case-insensitively (server_name may be mixed case). */
        if (wc[i].len - 2 == rest_len
            && ngx_strncasecmp(wc[i].data + 2, rest, rest_len) == 0)
        {
            return 1;
        }
    }

    return 0;
}


/*
 * D5: add one issuable name to the global set + its CA group (the per-name body
 * lifted out of postconfig so both the server_name loop and the autocert_wildcard
 * loop share it). Dedups against amcf->names; a name already claimed by a
 * different CA is an emerg (one name = one cert = one CA); a same-CA dup still
 * routes through ca_entry so its trust/EAB-conflict gate + email bind run.
 */
static ngx_int_t
ngx_http_autocert_add_name(ngx_conf_t *cf, ngx_http_autocert_main_conf_t *amcf,
    ngx_autocert_ca_conf_t *cac, ngx_http_autocert_srv_conf_t *ascf,
    ngx_str_t name)
{
    ngx_uint_t                i;
    ngx_autocert_ca_entry_t  *ce;
    ngx_str_t                *slot;

    /* Dedup: the same name may appear across vhosts. */
    for (i = 0; i < amcf->names->nelts; i++) {
        ngx_str_t  *e = &((ngx_str_t *) amcf->names->elts)[i];

        if (e->len == name.len
            && ngx_strncmp(e->data, name.data, name.len) == 0)
        {
            break;
        }
    }

    if (i < amcf->names->nelts) {
        /*
         * The name is already claimed by an earlier vhost. There is ONE stored
         * certificate per name, so it must resolve to ONE CA. If this vhost pins
         * it to a DIFFERENT CA than the one that first claimed it, that is an
         * ambiguous config (which CA signs the single cert?) — reject at parse
         * rather than silently keeping the first CA (Codex M5 LOW). Same CA =
         * the harmless dup we skip.
         */
        ngx_autocert_ca_entry_t  *owner = NULL;
        ngx_uint_t                k, m;

        ce = amcf->ca_list->elts;
        for (k = 0; k < amcf->ca_list->nelts && owner == NULL; k++) {
            ngx_str_t  *gn = ce[k].names->elts;
            for (m = 0; m < ce[k].names->nelts; m++) {
                if (gn[m].len == name.len
                    && ngx_strncmp(gn[m].data, name.data, name.len) == 0)
                {
                    owner = &ce[k];
                    break;
                }
            }
        }

        if (owner != NULL
            && (owner->ca_conf.ca.len != cac->ca.len
                || ngx_strncmp(owner->ca_conf.ca.data, cac->ca.data,
                               cac->ca.len) != 0))
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "autocert: server name \"%V\" is claimed by two vhosts "
                "with different CAs (\"%V\" vs \"%V\"); one name issues "
                "one certificate from one CA — pin it to a single CA",
                &name, &owner->ca_conf.ca, &cac->ca);
            return NGX_ERROR;
        }

        /* Dup name, same CA URL: this vhost adds no new name, but it must still
         * pass the SAME trust/EAB-conflict gate a name-contributing vhost does
         * (ngx_http_autocert_ca_entry rejects a same-URL group reconfigured with
         * a different ca_certificate/EAB), and its `autocert on <email>` binds to
         * the CA group's contact. Route through ca_entry so the dup path can't
         * bypass that validation; the entry already exists so no group grows. */
        if (owner != NULL) {
            ngx_autocert_ca_entry_t  *grp;

            grp = ngx_http_autocert_ca_entry(cf, amcf, cac);
            if (grp == NULL) {
                return NGX_ERROR;
            }
            if (ngx_http_autocert_bind_ca_email(cf, grp, &ascf->email)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        return NGX_OK;
    }

    slot = ngx_array_push(amcf->names);
    if (slot == NULL) {
        return NGX_ERROR;
    }

    *slot = name;

    /* M2: first-wins by CA — a new global name also joins the group of the CA of
     * the server that introduced it. Create the group lazily here (only now is
     * there a name for it) so no empty entry appears. ca_entry may grow ca_list
     * (realloc), so use the fresh `ce` at once — nothing else touches ca_list
     * before the push below. */
    ce = ngx_http_autocert_ca_entry(cf, amcf, cac);
    if (ce == NULL) {
        return NGX_ERROR;
    }
    if (ngx_http_autocert_bind_ca_email(cf, ce, &ascf->email) != NGX_OK) {
        return NGX_ERROR;
    }
    slot = ngx_array_push(ce->names);
    if (slot == NULL) {
        return NGX_ERROR;
    }
    *slot = name;

    return NGX_OK;
}


static ngx_int_t
ngx_http_autocert_postconfig(ngx_conf_t *cf)
{
    ngx_str_t                       name;
    ngx_uint_t                      s, n;
    ngx_http_server_name_t         *sn;
    ngx_http_autocert_srv_conf_t   *ascf;
    ngx_http_autocert_main_conf_t  *amcf;
    ngx_http_core_srv_conf_t      **cscfp, *cscf;
    ngx_http_core_main_conf_t      *cmcf;
    ngx_array_t                    *wc;
    ngx_autocert_ca_conf_t         *cac;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_autocert_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    amcf->names = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
    if (amcf->names == NULL) {
        return NGX_ERROR;
    }

    /* M2: per-CA name groups. One entry in the M1/M2 single-CA world. */
    amcf->ca_list = ngx_array_create(cf->pool, 2,
                                     sizeof(ngx_autocert_ca_entry_t));
    if (amcf->ca_list == NULL) {
        return NGX_ERROR;
    }

    /*
     * M4 (Codex #5): validate the http{}-level CA default even when no enabled
     * server reaches resolve_ca_conf() below. Before M4 the CA knobs were
     * http{}-global and init_main_conf validated them unconditionally; now the
     * per-server resolve is the only validation, so `http { autocert_staging on;
     * autocert_ca ...; }` with no `autocert on` anywhere would slip through.
     * Resolve a COPY of the main-level srv default (merge has already run, so
     * mutating the real one would be harmless, but a copy avoids a needless
     * second ca_certificate abspath pass on a value a server may also resolve).
     */
    {
        ngx_http_autocert_srv_conf_t  *amain;
        ngx_autocert_ca_conf_t         dflt;

        amain = ngx_http_conf_get_module_srv_conf(cf, ngx_http_autocert_module);
        dflt = amain->ca_conf;
        /* main-level srv_conf is never a merge child, so staging is still
         * NGX_CONF_UNSET (truthy!) when the directive was absent — default it
         * before resolve, exactly as merge_srv_conf does for real servers. */
        ngx_conf_init_value(dflt.staging, 0);
        if (ngx_http_autocert_resolve_ca_conf(cf, &dflt) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = cscfp[s];

        ascf = cscf->ctx->srv_conf[ngx_http_autocert_module.ctx_index];

        if (ascf->enable != 1) {
            continue;
        }

        /*
         * Account contact is per-CA: each CA's newAccount gets the first email
         * configured by a vhost in that CA group (bound below via
         * ngx_http_autocert_bind_ca_email, conflicts rejected). amcf->email keeps
         * the first-overall email only as a legacy fallback for a CA group whose
         * own vhosts set none.
         */
        if (amcf->email.len == 0 && ascf->email.len != 0) {
            amcf->email = ascf->email;
        }

        /* M4: this server's effective (merged) CA config, resolved + validated
         * in place — defaults the CA URL, applies staging<->ca exclusion, makes
         * ca_certificate absolute, enforces EAB both-or-neither. Must run before
         * the ca_list lookup, which keys on the resolved cac->ca URL. The
         * ca_list entry itself is created LAZILY below, only when a globally-new
         * name actually joins it, so a skip-only / duplicate-only server never
         * makes an empty CA group (the invariant M5 relies on). */
        cac = ngx_http_autocert_effective_ca(amcf, ascf);

        if (ngx_http_autocert_resolve_ca_conf(cf, cac) != NGX_OK) {
            return NGX_ERROR;
        }

        sn = cscf->server_names.elts;

        /* D5: this vhost's effective wildcard set (http{} default folded in by
         * merge_srv_conf). A declared wildcard is issuable only over dns-01 —
         * RFC 8555 §7.1.3 forbids a wildcard under http-01 / tls-alpn-01. */
        wc = (ascf->wildcards == NGX_CONF_UNSET_PTR) ? NULL : ascf->wildcards;

        if (wc != NULL && wc->nelts != 0
            && amcf->challenge != NGX_HTTP_AUTOCERT_CHALLENGE_DNS_01)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "autocert_wildcard requires \"autocert_challenge dns-01\" "
                "(a wildcard certificate can only be issued over dns-01)");
            return NGX_ERROR;
        }

        for (n = 0; n < cscf->server_names.nelts; n++) {
            name = sn[n].name;

            /*
             * Only concrete FQDNs are issuable. Skip:
             *  - regex names — nginx strips the leading '~' from sn->name, so
             *    test sn->regex, not the first byte (which is then '^', etc.).
             *  - wildcard forms — only a leading-label wildcard "*.rest" is
             *    issuable, and only via dns-01 (RFC 8555 §7.1.3 forbids http-01/
             *    tls-alpn-01 for a wildcard). Any other '*' (suffix ".*",
             *    embedded, or a leading wildcard under a non-dns-01 challenge)
             *    is rejected. A leading '.' (".rest") is never a concrete name.
             *  - the empty catch-all "".
             */
#if (NGX_PCRE)
            if (sn[n].regex != NULL) {
                continue;
            }
#endif
            if (name.len == 0 || name.data[0] == '.') {
                continue;
            }
            if (ngx_strlchr(name.data, name.data + name.len, '*') != NULL) {
                /* D4: keep "*.rest" only under dns-01 and only if it is the
                 * sole, leading-label wildcard. The order flow sends "*.rest" as
                 * the ACME identifier and stores it under "_wildcard_.rest". */
                if (amcf->challenge != NGX_HTTP_AUTOCERT_CHALLENGE_DNS_01
                    || !ngx_http_autocert_is_wildcard(&name))
                {
                    continue;
                }
            }

            /* D5: a concrete subdomain covered by one of this vhost's
             * autocert_wildcard entries is served from the wildcard cert, so do
             * not also issue a separate certificate for it. */
            if (wc != NULL && wc->nelts != 0
                && ngx_http_autocert_name_covered(&name, wc))
            {
                continue;
            }

            if (ngx_http_autocert_add_name(cf, amcf, cac, ascf, name)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
        }

        /* D5: add the wildcard SAN(s) declared via autocert_wildcard. They run
         * through the same dedup / one-name-one-CA / email-bind path as a
         * server_name-derived name. */
        if (wc != NULL) {
            ngx_str_t  *wn = wc->elts;

            for (n = 0; n < wc->nelts; n++) {
                if (ngx_http_autocert_add_name(cf, amcf, cac, ascf, wn[n])
                    != NGX_OK)
                {
                    return NGX_ERROR;
                }
            }
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "autocert: %ui name(s) enabled for issuance across %ui CA(s)",
                  amcf->names->nelts, amcf->ca_list->nelts);

    /*
     * M10b: when tls-alpn-01 is the configured challenge (or a test seed is
     * present), set up the challenge-cert store the helper writes and the
     * cert_cb reads. Created BEFORE serve_init so the latter sees amcf->alpn_zone
     * and installs the ALPN selection callback. Reuses its tree across reload
     * (noreuse off) so an in-flight challenge survives a reconfigure.
     */
    if ((amcf->challenge == NGX_HTTP_AUTOCERT_CHALLENGE_TLS_ALPN_01
         && amcf->names->nelts != 0)
        || amcf->test_alpn_domain.len != 0)
    {
        ngx_str_set(&name, "autocert_tls_alpn");

        amcf->alpn_zone = ngx_shared_memory_add(cf, &name,
                              NGX_HTTP_AUTOCERT_ALPN_ZONE_SIZE,
                              &ngx_http_autocert_module);
        if (amcf->alpn_zone == NULL) {
            return NGX_ERROR;
        }
        amcf->alpn_zone->init = ngx_autocert_alpn_init_zone;
        amcf->alpn_zone->data = amcf;
    }

    /*
     * M7: install per-SNI cert serving on every enabled ssl server (builds a
     * bootstrap SSL_CTX where the operator gave no ssl_certificate). Runs after
     * ssl merge has created the ctxs. Independent of whether any concrete name
     * was collected (a wildcard-only vhost still needs a working listener).
     */
    if (ngx_http_autocert_serve_init(cf, amcf) != NGX_OK) {
        return NGX_ERROR;
    }

    if (amcf->names->nelts == 0 && amcf->test_token.len == 0) {
        /* Nothing to provision and no test seed; skip both zones. */
        return NGX_OK;
    }

    /*
     * Challenge token store + the :80 serving handler. Set up whenever there is
     * something to provision (or a test seed). The zone reuses its tree across
     * reload (noreuse off) so in-flight challenges survive a reconfigure.
     */
    ngx_str_set(&name, "autocert_challenges");

    amcf->challenge_zone = ngx_shared_memory_add(cf, &name,
                               NGX_HTTP_AUTOCERT_CHALLENGE_ZONE_SIZE,
                               &ngx_http_autocert_module);
    if (amcf->challenge_zone == NULL) {
        return NGX_ERROR;
    }
    amcf->challenge_zone->init = ngx_autocert_challenge_init_zone;
    amcf->challenge_zone->data = amcf;

    {
        ngx_http_handler_pt        *h;
        ngx_http_core_main_conf_t  *cmcf2;

        cmcf2 = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
        h = ngx_array_push(&cmcf2->phases[NGX_HTTP_CONTENT_PHASE].handlers);
        if (h == NULL) {
            return NGX_ERROR;
        }
        *h = ngx_http_autocert_challenge_handler;
    }

    if (amcf->names->nelts == 0) {
        /* Test-seed only: no name zone needed. */
        return NGX_OK;
    }

    ngx_str_set(&name, "autocert");

    amcf->shm_zone = ngx_shared_memory_add(cf, &name,
                                           NGX_HTTP_AUTOCERT_ZONE_SIZE,
                                           &ngx_http_autocert_module);
    if (amcf->shm_zone == NULL) {
        return NGX_ERROR;
    }

    amcf->shm_zone->init = ngx_http_autocert_init_zone;
    amcf->shm_zone->data = amcf;
    amcf->shm_zone->noreuse = 1;

    return NGX_OK;
}


/*
 * Content-phase handler for HTTP-01 validation. If the request URI is
 * /.well-known/acme-challenge/<token>, look the token up in the challenge store
 * and return its key authorization as text/plain; otherwise decline so the
 * normal location handling proceeds. The token store is shared with the helper
 * which fills it during the order flow (M6); M5 proves the serve path.
 */
static ngx_int_t
ngx_http_autocert_challenge_handler(ngx_http_request_t *r)
{
    ngx_http_autocert_main_conf_t  *amcf;
    ngx_http_autocert_srv_conf_t   *ascf;
    ngx_str_t                       token, keyauth;
    ngx_buf_t                      *b;
    ngx_chain_t                     out;
    ngx_int_t                       rc;
    static const size_t             pfxlen =
                                        sizeof(NGX_HTTP_AUTOCERT_WK_PREFIX) - 1;

    if (r->uri.len < pfxlen
        || ngx_strncmp(r->uri.data, NGX_HTTP_AUTOCERT_WK_PREFIX, pfxlen) != 0)
    {
        return NGX_DECLINED;            /* not our path — let others handle it */
    }

    ascf = ngx_http_get_module_srv_conf(r, ngx_http_autocert_module);
    if (ascf == NULL || ascf->enable != 1) {
        return NGX_DECLINED;
    }

    /*
     * From here the request is under /.well-known/acme-challenge/ — it is ours.
     * Never NGX_DECLINED past this point, or a static/user handler could serve
     * a bogus challenge response. Anything malformed is a 4xx.
     */
    amcf = ngx_http_get_module_main_conf(r, ngx_http_autocert_module);
    if (amcf->challenge_zone == NULL) {
        return NGX_HTTP_NOT_FOUND;
    }

    if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
        /* RFC 9110 §15.5.6: a 405 MUST carry an Allow header. */
        ngx_table_elt_t  *allow;

        allow = ngx_list_push(&r->headers_out.headers);
        if (allow != NULL) {
            allow->hash = 1;
            ngx_str_set(&allow->key, "Allow");
            ngx_str_set(&allow->value, "GET, HEAD");
        }
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* the token is the single path segment after the prefix */
    token.data = r->uri.data + pfxlen;
    token.len = r->uri.len - pfxlen;
    if (token.len == 0
        || ngx_strlchr(token.data, token.data + token.len, '/') != NULL)
    {
        return NGX_HTTP_NOT_FOUND;
    }

    rc = ngx_autocert_challenge_get(amcf->challenge_zone, &token, r->pool,
                                    &keyauth);
    if (rc == NGX_DECLINED) {
        return NGX_HTTP_NOT_FOUND;
    }
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = keyauth.len;
    ngx_str_set(&r->headers_out.content_type, "text/plain");
    r->headers_out.content_type_len = r->headers_out.content_type.len;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b = ngx_create_temp_buf(r->pool, keyauth.len);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->last = ngx_cpymem(b->pos, keyauth.data, keyauth.len);
    b->last_buf = (r == r->main) ? 1 : 0;
    b->last_in_chain = 1;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}


/*
 * Populate the slab with the collected name set. noreuse=1 forces a fresh
 * zone on every (re)load, so this always (re)builds from the current config.
 * nginx still passes the *previous* cycle's zone data as `data`; we ignore it
 * — touching it would be a use-after-free once the old cycle is freed.
 */
static ngx_int_t
ngx_http_autocert_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_autocert_main_conf_t  *amcf = shm_zone->data;

    size_t                    sz;
    u_char                   *p;
    ngx_uint_t                i, nelts;
    ngx_str_t                *src;
    ngx_slab_pool_t          *shpool;
    ngx_http_autocert_sh_t   *sh;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    nelts = amcf->names->nelts;
    src = amcf->names->elts;

    /*
     * Guard the size_t multiply against overflow before sizing the slab.
     * nelts is bounded by config in practice, but a wrapped sz would
     * underallocate and let the copy loop corrupt the slab.
     */
    if (nelts > (NGX_MAX_SIZE_T_VALUE
                 - offsetof(ngx_http_autocert_sh_t, elts))
                / sizeof(ngx_str_t))
    {
        ngx_log_error(NGX_LOG_EMERG, shm_zone->shm.log, 0,
                      "autocert: too many names (%ui) for zone", nelts);
        return NGX_ERROR;
    }

    sz = offsetof(ngx_http_autocert_sh_t, elts) + nelts * sizeof(ngx_str_t);

    sh = ngx_slab_calloc(shpool, sz);
    if (sh == NULL) {
        return NGX_ERROR;
    }

    sh->nelts = nelts;

    for (i = 0; i < nelts; i++) {
        p = ngx_slab_alloc(shpool, src[i].len);
        if (p == NULL) {
            /* Slab is mmap-backed and survives a failed reload, so free what we
             * already allocated before bailing — otherwise a repeatedly-failing
             * reload permanently wastes slab space. */
            ngx_uint_t  j;

            for (j = 0; j < i; j++) {
                ngx_slab_free(shpool, sh->elts[j].data);
            }
            ngx_slab_free(shpool, sh);
            return NGX_ERROR;
        }

        ngx_memcpy(p, src[i].data, src[i].len);
        sh->elts[i].len = src[i].len;
        sh->elts[i].data = p;
    }

    shpool->data = sh;

    return NGX_OK;
}


/*
 * autocert_resolver <addr> [addr...];
 *
 * Build the ngx_resolver the helper uses for outbound ACME DNS. Created at
 * config time so it lives in the cycle pool and is reachable from the helper
 * process (same cycle); the helper has no ngx_conf_t to build one itself.
 */
static char *
ngx_http_autocert_resolver(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;

    ngx_str_t  *value = cf->args->elts;

    if (amcf->resolver != NULL) {
        return "is duplicate";
    }

    amcf->resolver = ngx_resolver_create(cf, &value[1], cf->args->nelts - 1);
    if (amcf->resolver == NULL) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/*
 * autocert on|off [email];
 *
 * arg[1] is the on/off flag; optional arg[2] is the ACME account email.
 */
static char *
ngx_http_autocert(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_srv_conf_t  *ascf = conf;

    ngx_str_t  *value;

    if (ascf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        ascf->enable = 1;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "autocert: directive parsed: on (cmd_type %xi)",
                       cf->cmd_type);

        /*
         * Make nginx build the server's SSL_CTX even though the operator gave
         * no ssl_certificate. ngx_http_ssl_module's merge returns before
         * ngx_ssl_create when sscf->certificates == NULL, and its postconfig
         * (ngx_http_ssl_init) rejects a `listen ssl` server with no
         * certificates. Both gate on sscf->certificates being non-NULL — so we
         * seed EMPTY certificates + certificate_keys arrays here, at parse time
         * (before any merge/postconfig, dodging the module-order problem that
         * blocks a dynamic module from hooking earlier). ssl then creates a
         * fully nginx-wired ctx (ALPN, servername cb, ciphers, session cache)
         * that loads zero certs; ngx_http_autocert_serve_init installs a
         * bootstrap cert + the per-SNI cert_cb on top.
         *
         * Seed ONLY for a server{}-level `autocert on` (NGX_HTTP_SRV_CONF in
         * cmd_type). The http{}-level global occurrence writes the template srv
         * conf that EVERY server inherits via merge_ptr — seeding there would
         * give a plain `listen 80;` vhost empty cert arrays too, which makes ssl
         * build a pointless ctx and trips the no-cert checks. A server that
         * wants autocert TLS serving therefore carries its own `autocert on`
         * (the documented form). Skip if the operator already set
         * ssl_certificate (UNSET_PTR test).
         */
        if (cf->cmd_type & NGX_HTTP_SRV_CONF) {
            ngx_http_ssl_srv_conf_t  *sscf;

            sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);

            if (sscf != NULL && sscf->certificates == NGX_CONF_UNSET_PTR) {
                sscf->certificates = ngx_array_create(cf->pool, 1,
                                                      sizeof(ngx_str_t));
                sscf->certificate_keys = ngx_array_create(cf->pool, 1,
                                                          sizeof(ngx_str_t));
                if (sscf->certificates == NULL
                    || sscf->certificate_keys == NULL)
                {
                    return NGX_CONF_ERROR;
                }
            }
        }

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        ascf->enable = 0;

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "autocert: directive parsed: off");

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"autocert\" directive, "
                           "expected \"on\" or \"off\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/* ACME account contact email (autocert_contact <email>). Split out of the old
 * `autocert on <email>` positional arg for config clarity; per-CA resolution
 * (first non-empty contact in a CA group) is unchanged. */
static char *
ngx_http_autocert_contact(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_srv_conf_t  *ascf = conf;
    ngx_str_t                     *value = cf->args->elts;
    u_char                        *at;

    if (ascf->email.len != 0) {
        return "is duplicate";
    }

    /*
     * Minimal validation: an ACME contact must look like an email (a single
     * '@' with text either side). Full RFC validation is the CA's job; this
     * only catches obvious config typos.
     */
    at = ngx_strlchr(value[1].data, value[1].data + value[1].len, '@');

    if (at == NULL
        || at == value[1].data
        || at == value[1].data + value[1].len - 1
        || ngx_strlchr(at + 1, value[1].data + value[1].len, '@') != NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid email \"%V\" in \"autocert_contact\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    ascf->email = value[1];

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "autocert: account contact \"%V\"", &ascf->email);

    return NGX_CONF_OK;
}


static char *
ngx_http_autocert_key_type(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;

    ngx_str_t  *value = cf->args->elts;

    if (amcf->key_type != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    /* Accept friendly aliases alongside the OpenSSL curve names: operators
     * think "P-384"/"P-256", not "secp384r1"/"secp256r1". */
    if (ngx_strcasecmp(value[1].data, (u_char *) "secp384r1") == 0
        || ngx_strcasecmp(value[1].data, (u_char *) "p384") == 0
        || ngx_strcasecmp(value[1].data, (u_char *) "p-384") == 0
        || ngx_strcasecmp(value[1].data, (u_char *) "ecdsa-p384") == 0)
    {
        amcf->key_type = NGX_HTTP_AUTOCERT_KEY_P384;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "secp256r1") == 0
               || ngx_strcasecmp(value[1].data, (u_char *) "prime256v1") == 0
               || ngx_strcasecmp(value[1].data, (u_char *) "p256") == 0
               || ngx_strcasecmp(value[1].data, (u_char *) "p-256") == 0
               || ngx_strcasecmp(value[1].data, (u_char *) "ecdsa-p256") == 0)
    {
        amcf->key_type = NGX_HTTP_AUTOCERT_KEY_P256;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid key type \"%V\" in \"autocert_key_type\", "
                           "expected p384 (secp384r1) or p256 (secp256r1)",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_autocert_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;

    ngx_str_t  *value = cf->args->elts;

    if (amcf->store != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    /* "default" is the module's own hardened layout (was "secure" — renamed so
     * it doesn't imply the certbot layout is insecure). "secure" still accepted. */
    if (ngx_strcmp(value[1].data, "default") == 0
        || ngx_strcmp(value[1].data, "secure") == 0)
    {
        amcf->store = NGX_HTTP_AUTOCERT_STORE_SECURE;

    } else if (ngx_strcmp(value[1].data, "certbot") == 0) {
        amcf->store = NGX_HTTP_AUTOCERT_STORE_CERTBOT;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid layout \"%V\" in \"autocert_store_layout\", "
                           "expected \"default\" or \"certbot\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_autocert_challenge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;

    ngx_str_t  *value = cf->args->elts;

    if (amcf->challenge != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (ngx_strcmp(value[1].data, "http-01") == 0) {
        amcf->challenge = NGX_HTTP_AUTOCERT_CHALLENGE_HTTP_01;

    } else if (ngx_strcmp(value[1].data, "tls-alpn-01") == 0) {
        amcf->challenge = NGX_HTTP_AUTOCERT_CHALLENGE_TLS_ALPN_01;

    } else if (ngx_strcmp(value[1].data, "dns-01") == 0) {
        amcf->challenge = NGX_HTTP_AUTOCERT_CHALLENGE_DNS_01;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid challenge \"%V\" in \"autocert_challenge\", "
                           "expected \"http-01\", \"tls-alpn-01\" or \"dns-01\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


#if (NGX_AUTOCERT_TEST)

/*
 * autocert_test_challenge <token> <keyauth>;  (TEST-ONLY)
 *
 * Records a single token/keyauth pair in the main conf; the helper inserts it
 * into the challenge store at startup. Lets CI fetch
 * /.well-known/acme-challenge/<token> and assert <keyauth> without running a
 * real ACME order. Bounded to the same limits the store enforces.
 */
static char *
ngx_http_autocert_test_challenge(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;
    ngx_str_t                      *value = cf->args->elts;

    if (amcf->test_token.len != 0) {
        return "is duplicate";
    }

    if (value[1].len == 0 || value[1].len > NGX_AUTOCERT_TOKEN_MAX
        || value[2].len == 0 || value[2].len > NGX_AUTOCERT_KEYAUTH_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid token/keyauth length in "
                           "\"autocert_test_challenge\"");
        return NGX_CONF_ERROR;
    }

    if (ngx_strlchr(value[1].data, value[1].data + value[1].len, '/')
        != NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "token must not contain '/' in "
                           "\"autocert_test_challenge\"");
        return NGX_CONF_ERROR;
    }

    amcf->test_token = value[1];
    amcf->test_keyauth = value[2];

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"autocert_test_challenge\" is test-only and should "
                       "not be used in production configs");

    return NGX_CONF_OK;
}


/*
 * autocert_test_alpn <domain> <keyauth>;  (TEST-ONLY)
 *
 * Records a single domain/keyauth pair in the main conf; the helper builds the
 * RFC 8737 challenge certificate for it at startup and inserts it into the ALPN
 * store. Lets CI negotiate ALPN "acme-tls/1" + SNI=<domain> and assert the
 * acmeIdentifier cert is served, without running a real ACME order. Bounded to
 * the same limits the store enforces.
 */
static char *
ngx_http_autocert_test_alpn(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;
    ngx_str_t                      *value = cf->args->elts;

    if (amcf->test_alpn_domain.len != 0) {
        return "is duplicate";
    }

    if (value[1].len == 0 || value[1].len > NGX_AUTOCERT_ALPN_DOMAIN_MAX
        || value[2].len == 0 || value[2].len > NGX_AUTOCERT_KEYAUTH_MAX)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid domain/keyauth length in "
                           "\"autocert_test_alpn\"");
        return NGX_CONF_ERROR;
    }

    if (value[1].data[0] == '.'
        || ngx_strlchr(value[1].data, value[1].data + value[1].len, '/')
           != NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid domain in \"autocert_test_alpn\"");
        return NGX_CONF_ERROR;
    }

    amcf->test_alpn_domain = value[1];
    amcf->test_alpn_keyauth = value[2];

    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "\"autocert_test_alpn\" is test-only and should "
                       "not be used in production configs");

    return NGX_CONF_OK;
}

#endif /* NGX_AUTOCERT_TEST */
