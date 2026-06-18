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

#include "ngx_http_autocert_conf.h"


#define NGX_HTTP_AUTOCERT_DEFAULT_CA \
    "https://acme-v02.api.letsencrypt.org/directory"

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

    if (amcf->names->nelts == 0) {
        /* Nothing to provision; skip the zone entirely. */
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
