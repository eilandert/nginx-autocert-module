/*
 * ngx_autocert_conf — accessor that lets the CORE helper module read the HTTP
 * autocert module's main configuration. Compiled INTO the CORE process module
 * (not the HTTP module), because the two ship as separate dlopen()ed .so files
 * with no cross-module symbol resolution (see ngx_http_autocert_conf.h).
 *
 * It cannot reference ngx_http_autocert_module directly (that symbol lives in
 * the other .so), so it locates the HTTP module by NAME in cycle->modules[] to
 * get its ctx_index. ngx_http_module is a builtin exported by the server
 * binary, so it resolves fine from either .so.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_autocert_conf.h"
#include "ngx_autocert_shared.h"


ngx_int_t
ngx_autocert_get_conf(ngx_cycle_t *cycle, ngx_autocert_conf_t *out)
{
    ngx_uint_t                      i;
    ngx_uint_t                      ctx_index;
    ngx_uint_t                      found;
    ngx_http_conf_ctx_t            *http_ctx;
    ngx_http_autocert_main_conf_t  *amcf;

    if (out == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(ngx_autocert_conf_t));

    /* No http{} block -> no autocert config. */
    if (cycle->conf_ctx[ngx_http_module.index] == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: no http{} block, no autocert config");
        return NGX_OK;
    }

    /* Locate the HTTP autocert module by name to get its ctx_index. */
    found = 0;
    ctx_index = 0;
    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->type == NGX_HTTP_MODULE
            && cycle->modules[i]->name != NULL
            && ngx_strcmp(cycle->modules[i]->name,
                          "ngx_http_autocert_module") == 0)
        {
            ctx_index = cycle->modules[i]->ctx_index;
            found = 1;
            break;
        }
    }

    if (!found) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: ngx_http_autocert_module not loaded");
        return NGX_OK;                 /* HTTP module not loaded */
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: found ngx_http_autocert_module ctx_index:%ui",
                   ctx_index);

    http_ctx = (ngx_http_conf_ctx_t *) cycle->conf_ctx[ngx_http_module.index];

    amcf = http_ctx->main_conf[ctx_index];
    if (amcf == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "autocert: http main_conf absent, not configured");
        return NGX_OK;
    }

    out->configured = 1;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                   "autocert: resolved http conf, challenge:%ui names:%ui",
                   amcf->challenge,
                   amcf->names ? amcf->names->nelts : (ngx_uint_t) 0);
    out->ca = amcf->ca;
    out->resolver = amcf->resolver;
    out->resolver_timeout = amcf->resolver_timeout;
    out->ca_certificate = amcf->ca_certificate;
    out->key_type = amcf->key_type;
    out->store = amcf->store;
    out->path = amcf->path;
    out->renew_before = amcf->renew_before;
    out->challenge = amcf->challenge;
    out->challenge_zone = amcf->challenge_zone;
    out->names = amcf->names;
    out->test_token = amcf->test_token;
    out->test_keyauth = amcf->test_keyauth;
    out->alpn_zone = amcf->alpn_zone;
    out->test_alpn_domain = amcf->test_alpn_domain;
    out->test_alpn_keyauth = amcf->test_alpn_keyauth;

    /*
     * Fall back to the http{}-level `resolver` directive when autocert_resolver
     * is not set: the core resolver lives in the http main-level core location
     * conf. This lets operators configure DNS once for the whole instance.
     */
    if (out->resolver == NULL) {
        ngx_http_core_loc_conf_t  *clcf;

        clcf = http_ctx->loc_conf[ngx_http_core_module.ctx_index];
        if (clcf != NULL && clcf->resolver != NULL
            && clcf->resolver->connections.nelts > 0)
        {
            out->resolver = clcf->resolver;
        }
    }

    return NGX_OK;
}
