/*
 * ngx_http_autocert_module — automatic ACME certificate provisioning.
 *
 * M0 scaffold: module skeleton plus the `autocert on|off [email];` directive,
 * valid in both the http{} block (global) and a server{} block (per-vhost).
 * A per-vhost setting overrides the global one. No ACME logic yet — later
 * milestones add the helper process (M1), config model (M2) and ACME client
 * (M4+). Builds and loads on both nginx and angie.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_flag_t   enable;    /* autocert on|off; NGX_CONF_UNSET until set */
    ngx_str_t    email;     /* optional ACME account contact, "" if absent */
} ngx_http_autocert_conf_t;


static void *ngx_http_autocert_create_conf(ngx_conf_t *cf);
static char *ngx_http_autocert_merge_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_http_autocert(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_http_autocert_commands[] = {

    /*
     * Valid in http{} and server{}. gzip-style pattern: MAIN|SRV flags but a
     * single SRV-level conf + SRV_CONF_OFFSET. The http{} occurrence writes
     * into the main-level srv_conf slot; ngx_http_merge_servers() then merges
     * that into every server, giving global default + per-vhost override with
     * no separate main_conf. Final merge default is a concrete 0 (disabled).
     */
    { ngx_string("autocert"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE12,
      ngx_http_autocert,
      NGX_HTTP_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_autocert_module_ctx = {
    NULL,                              /* preconfiguration */
    NULL,                              /* postconfiguration */

    NULL,                              /* create main configuration */
    NULL,                              /* init main configuration */

    ngx_http_autocert_create_conf,     /* create server configuration */
    ngx_http_autocert_merge_conf,      /* merge server configuration */

    NULL,                              /* create location configuration */
    NULL                               /* merge location configuration */
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
ngx_http_autocert_create_conf(ngx_conf_t *cf)
{
    ngx_http_autocert_conf_t  *acf;

    acf = ngx_pcalloc(cf->pool, sizeof(ngx_http_autocert_conf_t));
    if (acf == NULL) {
        return NULL;
    }

    /* acf->email is zeroed by pcalloc */
    acf->enable = NGX_CONF_UNSET;

    return acf;
}


static char *
ngx_http_autocert_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_autocert_conf_t  *prev = parent;
    ngx_http_autocert_conf_t  *conf = child;

    /* A server{} setting overrides the http{} global; otherwise inherit. */
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->email, prev->email, "");

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
    ngx_http_autocert_conf_t  *acf = conf;

    ngx_str_t  *value;

    if (acf->enable != NGX_CONF_UNSET) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_strcasecmp(value[1].data, (u_char *) "on") == 0) {
        acf->enable = 1;

    } else if (ngx_strcasecmp(value[1].data, (u_char *) "off") == 0) {
        acf->enable = 0;

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

        acf->email = value[2];
    }

    return NGX_CONF_OK;
}
