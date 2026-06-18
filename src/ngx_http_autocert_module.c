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

#include "ngx_http_autocert_conf.h"
#include "ngx_autocert_challenge.h"
#include "ngx_autocert_serve.h"


#define NGX_HTTP_AUTOCERT_DEFAULT_CA \
    "https://acme-v02.api.letsencrypt.org/directory"

#define NGX_HTTP_AUTOCERT_WK_PREFIX  "/.well-known/acme-challenge/"

/* Challenge token store zone: small; one node per in-flight authorization. */
#define NGX_HTTP_AUTOCERT_CHALLENGE_ZONE_SIZE  (128 * 1024)

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
static char *ngx_http_autocert_test_challenge(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);

static char *ngx_http_autocert(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_autocert_key_type(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_store(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_challenge(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_autocert_resolver(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_command_t  ngx_http_autocert_commands[] = {

    /*
     * Valid in http{} and server{}. gzip-style: a single SRV-level conf with
     * SRV_CONF_OFFSET; the http{} occurrence writes the main-level srv_conf
     * slot, which ngx_http_merge_servers() then folds into every server,
     * giving a global default plus per-vhost override.
     */
    { ngx_string("autocert"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_autocert,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

    /* The tuning knobs below are http{}-global only (one ACME policy). */

    { ngx_string("autocert_ca"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, ca),
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

    { ngx_string("autocert_store"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_autocert_store,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("autocert_path"),
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

    { ngx_string("autocert_ca_certificate"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_autocert_main_conf_t, ca_certificate),
      NULL },

    /* TEST-ONLY: seed one token->keyauth into the challenge store at startup so
     * the HTTP-01 serve path can be tested before the order flow (M6) exists.
     * Not for production use. */
    { ngx_string("autocert_test_challenge"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_autocert_test_challenge,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


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
    NULL,                              /* init module */
    NULL,                              /* init process */
    NULL,                              /* init thread */
    NULL,                              /* exit thread */
    NULL,                              /* exit process */
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

    /* ca, path zeroed by pcalloc; set in init_main_conf. */
    amcf->renew_before = NGX_CONF_UNSET;
    amcf->key_type = NGX_CONF_UNSET_UINT;
    amcf->store = NGX_CONF_UNSET_UINT;
    amcf->challenge = NGX_CONF_UNSET_UINT;

    /* resolver pointer + ca_certificate zeroed by pcalloc */
    amcf->resolver_timeout = NGX_CONF_UNSET;

    return amcf;
}


static char *
ngx_http_autocert_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_autocert_main_conf_t  *amcf = conf;

    if (amcf->ca.data == NULL) {
        ngx_str_set(&amcf->ca, NGX_HTTP_AUTOCERT_DEFAULT_CA);
    }

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

    return NGX_CONF_OK;
}


/*
 * Run after the whole http{} config is parsed and merged. Walk every server,
 * and for each one with autocert enabled, copy its server_name strings into
 * the main-conf name array (deduplicated). Then size and register the shared
 * zone that publishes that set to the helper process.
 */
static ngx_int_t
ngx_http_autocert_postconfig(ngx_conf_t *cf)
{
    ngx_str_t                       name;
    ngx_uint_t                      s, n, i;
    ngx_http_server_name_t         *sn;
    ngx_http_autocert_srv_conf_t   *ascf;
    ngx_http_autocert_main_conf_t  *amcf;
    ngx_http_core_srv_conf_t      **cscfp, *cscf;
    ngx_http_core_main_conf_t      *cmcf;

    amcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_autocert_module);
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    amcf->names = ngx_array_create(cf->pool, 8, sizeof(ngx_str_t));
    if (amcf->names == NULL) {
        return NGX_ERROR;
    }

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = cscfp[s];

        ascf = cscf->ctx->srv_conf[ngx_http_autocert_module.ctx_index];

        if (ascf->enable != 1) {
            continue;
        }

        sn = cscf->server_names.elts;

        for (n = 0; n < cscf->server_names.nelts; n++) {
            name = sn[n].name;

            /*
             * Only concrete FQDNs are issuable. Skip:
             *  - regex names — nginx strips the leading '~' from sn->name, so
             *    test sn->regex, not the first byte (which is then '^', etc.).
             *  - wildcard forms — leading '*.'/'.'  AND trailing '.*' (suffix
             *    wildcard, also stored without the leading char): reject any
             *    '*' anywhere in the name. A single ACME order can't cover
             *    these (DNS-01 wildcard support is deferred).
             *  - the empty catch-all "".
             */
#if (NGX_PCRE)
            if (sn[n].regex != NULL) {
                continue;
            }
#endif
            if (name.len == 0
                || name.data[0] == '.'
                || ngx_strlchr(name.data, name.data + name.len, '*') != NULL)
            {
                continue;
            }

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
                continue;
            }

            ngx_str_t  *slot = ngx_array_push(amcf->names);
            if (slot == NULL) {
                return NGX_ERROR;
            }

            *slot = name;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "autocert: %ui name(s) enabled for issuance",
                  amcf->names->nelts);

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

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid value \"%V\" in \"autocert\" directive, "
                           "expected \"on\" or \"off\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (cf->args->nelts == 3) {
        /*
         * Minimal validation: an ACME contact must look like an email
         * (contain a single '@' with text either side). Full RFC validation
         * is the CA's job; this only catches obvious config typos.
         */
        u_char  *at;

        at = ngx_strlchr(value[2].data, value[2].data + value[2].len, '@');

        if (at == NULL
            || at == value[2].data
            || at == value[2].data + value[2].len - 1
            || ngx_strlchr(at + 1, value[2].data + value[2].len, '@') != NULL)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid email \"%V\" in \"autocert\" directive",
                               &value[2]);
            return NGX_CONF_ERROR;
        }

        ascf->email = value[2];
    }

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

    if (ngx_strcmp(value[1].data, "secp384r1") == 0) {
        amcf->key_type = NGX_HTTP_AUTOCERT_KEY_P384;

    } else if (ngx_strcmp(value[1].data, "secp256r1") == 0) {
        amcf->key_type = NGX_HTTP_AUTOCERT_KEY_P256;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid key type \"%V\" in \"autocert_key_type\", "
                           "expected \"secp384r1\" or \"secp256r1\"",
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

    if (ngx_strcmp(value[1].data, "secure") == 0) {
        amcf->store = NGX_HTTP_AUTOCERT_STORE_SECURE;

    } else if (ngx_strcmp(value[1].data, "certbot") == 0) {
        amcf->store = NGX_HTTP_AUTOCERT_STORE_CERTBOT;

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid store \"%V\" in \"autocert_store\", "
                           "expected \"secure\" or \"certbot\"", &value[1]);
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

    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid challenge \"%V\" in \"autocert_challenge\", "
                           "expected \"http-01\" or \"tls-alpn-01\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


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

    return NGX_CONF_OK;
}
