/*
 * ngx_autocert_serve — per-SNI certificate serving (M7).
 * See ngx_autocert_serve.h for the contract.
 */

#include "ngx_autocert_serve.h"
#include "ngx_autocert_alpn.h"
#include "ngx_http_autocert_crypto.h"

#include <ngx_http_ssl_module.h>
#if (NGX_HTTP_V2)
#include <ngx_http_v2_module.h>
#endif
#if (NGX_HTTP_V3)
#include <ngx_http_v3.h>
#endif

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>


/*
 * The RFC 8737 application protocol the ACME validation client negotiates. We
 * select it (in the ALPN callback) and detect it (in the cert callback) to
 * decide whether to serve the challenge certificate instead of the real one.
 */
#define NGX_AUTOCERT_ACME_TLS_ALPN      "acme-tls/1"
#define NGX_AUTOCERT_ACME_TLS_ALPN_LEN  (sizeof(NGX_AUTOCERT_ACME_TLS_ALPN) - 1)

/*
 * VENDORED from src/http/modules/ngx_http_ssl_module.c (a private #define
 * there). Our ALPN callback replaces nginx's on autocert-enabled SSL_CTXs
 * (OpenSSL exposes no getter to chain to the original), so the normal-path
 * negotiation below must mirror nginx's advertised protocol set.
 * KEEP IN SYNC with nginx/angie.
 */
#define NGX_AUTOCERT_HTTP_ALPN_PROTOS   "\x08http/1.1\x08http/1.0\x08http/0.9"


/*
 * One cached certificate, keyed by SNI host. Lives for the life of the worker
 * process in a static rbtree; the cert/key OpenSSL objects are refcounted and
 * handed to each connection's SSL via SSL_use_*. mtime is the fullchain.pem
 * mtime observed at load; a renewal rewrites the files (M6b stores atomically),
 * so a changed mtime triggers a reload on the next handshake.
 */
typedef struct {
    ngx_str_node_t      sn;          /* {node (key=crc32), str=host}; first! */
    X509               *cert;        /* leaf; NULL when no cert on disk yet */
    STACK_OF(X509)     *chain;       /* intermediates (may be empty) */
    EVP_PKEY           *key;
    time_t              mtime;       /* fullchain.pem mtime at load */
    time_t              checked;     /* last time we stat()'d, coarse */
} ngx_autocert_cert_t;


/* cert_cb argument: the store config the worker reads certs from. */
typedef struct {
    ngx_str_t           path;        /* absolute store dir */
    ngx_uint_t          store;       /* ngx_http_autocert_store_e */
    ngx_array_t        *names;       /* ngx_str_t: the issuable name set */
    ngx_shm_zone_t     *alpn_zone;   /* M10b tls-alpn-01 cert store; NULL=off */
} ngx_autocert_serve_ctx_t;


/*
 * SSL-connection ex_data slot: set to (void *) 1 by our ALPN callback when it
 * selects "acme-tls/1", read by the cert callback to switch to the challenge
 * cert. An explicit flag (rather than SSL_get0_alpn_selected) makes the cert
 * callback independent of OpenSSL's callback ordering. Allocated once.
 */
static int  ngx_autocert_alpn_conn_index = -1;


/*
 * Per-worker cache. Static (process-global): one tree shared by every autocert
 * server in the worker, since a name is unique across the instance. Guarded by
 * nothing — nginx workers are single-threaded for the SSL handshake path, and
 * the cache is touched only from cert_cb on that thread.
 */
static ngx_rbtree_t         ngx_autocert_cache_rbtree;
static ngx_rbtree_node_t    ngx_autocert_cache_sentinel;
static ngx_pool_t          *ngx_autocert_cache_pool;     /* NULL until first use */


static int ngx_http_autocert_cert_cb(SSL *ssl_conn, void *arg);
static ngx_int_t ngx_http_autocert_cache_reload(ngx_autocert_cert_t *c,
    ngx_str_t *host, ngx_autocert_serve_ctx_t *sctx, ngx_log_t *log);
static ngx_int_t ngx_http_autocert_install_dummy(SSL_CTX *ctx, ngx_log_t *log);
static ngx_int_t ngx_http_autocert_read_file(ngx_pool_t *pool,
    u_char *path, ngx_str_t *out, time_t *mtime);
static int ngx_http_autocert_alpn_select(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg);
static int ngx_http_autocert_alpn_default(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen);
static int ngx_http_autocert_serve_alpn_cert(ngx_connection_t *c,
    SSL *ssl_conn, ngx_autocert_serve_ctx_t *sctx, ngx_str_t *host);


ngx_int_t
ngx_http_autocert_serve_init(ngx_conf_t *cf,
    ngx_http_autocert_main_conf_t *amcf)
{
    ngx_uint_t                     s;
    ngx_http_core_srv_conf_t     **cscfp, *cscf;
    ngx_http_core_main_conf_t     *cmcf;
    ngx_http_autocert_srv_conf_t  *ascf;
    ngx_http_ssl_srv_conf_t       *sscf;
    ngx_autocert_serve_ctx_t      *sctx;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    /* Shared cert_cb argument: store path + layout, in the cycle pool. */
    sctx = ngx_palloc(cf->pool, sizeof(ngx_autocert_serve_ctx_t));
    if (sctx == NULL) {
        return NGX_ERROR;
    }
    sctx->path = amcf->path;
    sctx->store = amcf->store;
    sctx->names = amcf->names;       /* bounds the per-worker cache */
    sctx->alpn_zone = amcf->alpn_zone;  /* M10b: NULL unless tls-alpn-01 wired */

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                   "autocert: serve init path \"%V\" names:%ui alpn:%ui",
                   &sctx->path,
                   sctx->names ? sctx->names->nelts : 0,
                   sctx->alpn_zone != NULL);

    /*
     * Allocate the per-connection ex_data slot the ALPN callback uses to flag
     * an acme-tls/1 handshake for the cert callback. Once per process; -1 means
     * "not yet allocated". Only needed when the tls-alpn-01 path is active.
     */
    if (sctx->alpn_zone != NULL && ngx_autocert_alpn_conn_index == -1) {
        ngx_autocert_alpn_conn_index =
            SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (ngx_autocert_alpn_conn_index == -1) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "autocert: SSL_get_ex_new_index() failed");
            return NGX_ERROR;
        }
    }

    cscfp = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = cscfp[s];

        ascf = cscf->ctx->srv_conf[ngx_http_autocert_module.ctx_index];
        sscf = cscf->ctx->srv_conf[ngx_http_ssl_module.ctx_index];

        if (ascf->enable != 1) {
            /*
             * Disabled server. A child `server { autocert off; listen ssl; }`
             * under an http-level `autocert on;` INHERITS the empty bootstrap
             * cert arrays we seeded at parse time (merge_ptr copies the parent
             * pointer), which fools nginx's "has certificates" check but leaves
             * a ctx with no cert and no cert_cb here. Reject that explicitly
             * rather than let it serve a certless handshake. A real
             * ssl_certificate (nelts > 0) on the disabled child is fine.
             */
            if (sscf->ssl.ctx != NULL
                && sscf->certificates != NULL
                && sscf->certificates->nelts == 0
                && sscf->certificate_values == NULL)
            {
                ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                              "autocert: server with \"autocert off\" and a "
                              "\"listen ... ssl\" listener has no "
                              "\"ssl_certificate\"");
                return NGX_ERROR;
            }
            continue;
        }

        /*
         * Enabled. A plain `autocert on;` server had empty cert arrays seeded
         * at parse time so ssl built a ctx with no certs; a server with a real
         * ssl_certificate has its own. No ctx => autocert-enabled without an
         * ssl listener, a no-op for serving.
         */
        if (sscf->ssl.ctx == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                           "autocert: server \"%V\" has no SSL_CTX, "
                           "skipping cert_cb install", &cscf->server_name);
            continue;
        }

        /*
         * Variable ssl_certificate (ssl_certificate with a $var) installs
         * nginx's own dynamic cert_cb. We'd clobber it below, and our store
         * lookup can't honour the operator's per-request cert logic. Reject the
         * combination rather than silently break it.
         */
        if (sscf->certificate_values != NULL) {
            ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                          "autocert: \"autocert on\" is incompatible with a "
                          "variable \"ssl_certificate\"");
            return NGX_ERROR;
        }

        /*
         * No real cert configured (empty certificates array, nothing on the
         * ctx): seed a self-signed bootstrap cert so the handshake completes
         * before the first issuance. A server with a real ssl_certificate keeps
         * it as the fallback; we only override per-SNI.
         */
        if (sscf->certificates != NULL
            && sscf->certificates->nelts == 0
            && SSL_CTX_get0_certificate(sscf->ssl.ctx) == NULL)
        {
            if (ngx_http_autocert_install_dummy(sscf->ssl.ctx, cf->log)
                != NGX_OK)
            {
                return NGX_ERROR;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                           "autocert: installed bootstrap cert for \"%V\"",
                           &cscf->server_name);
        }

        /* Install the per-SNI cert callback (overrides whatever is on the ctx). */
        SSL_CTX_set_cert_cb(sscf->ssl.ctx, ngx_http_autocert_cert_cb, sctx);
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                       "autocert: installed cert_cb for \"%V\"",
                       &cscf->server_name);

        /*
         * M10b: when tls-alpn-01 is active, replace nginx's ALPN selection
         * callback with ours so the CA's "acme-tls/1" validation handshake is
         * accepted; ours reproduces nginx's h2/http negotiation for every other
         * client (see ngx_http_autocert_alpn_select). Only when alpn_zone is
         * set, so an http-01-only deployment keeps nginx's callback untouched.
         */
        if (sctx->alpn_zone != NULL) {
            SSL_CTX_set_alpn_select_cb(sscf->ssl.ctx,
                                       ngx_http_autocert_alpn_select, sctx);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, cf->log, 0,
                           "autocert: installed ALPN callback for \"%V\"",
                           &cscf->server_name);
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_autocert_install_dummy(SSL_CTX *ctx, ngx_log_t *log)
{
    EVP_PKEY  *key;
    X509      *cert;
    ngx_int_t  rc = NGX_ERROR;

    /* P-256 throwaway key is plenty for a cert no client ever validates. */
    key = ngx_http_autocert_key_generate(NGX_HTTP_AUTOCERT_KEY_P256);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "autocert: bootstrap key generation failed");
        return NGX_ERROR;
    }

    cert = ngx_http_autocert_dummy_cert(key);
    if (cert == NULL) {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "autocert: bootstrap certificate generation failed");
        goto done;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1
        || SSL_CTX_use_PrivateKey(ctx, key) != 1)
    {
        ngx_log_error(NGX_LOG_EMERG, log, 0,
                      "autocert: installing bootstrap certificate failed");
        goto done;
    }

    rc = NGX_OK;

done:

    /* SSL_CTX_use_* up-ref on success; drop our refs either way. */
    if (cert != NULL) {
        X509_free(cert);
    }
    ngx_http_autocert_key_free(key);

    return rc;
}


/*
 * OpenSSL certificate callback, run once per handshake after ClientHello.
 * Resolve the SNI host, ensure a fresh cert is cached, and bind it to this
 * connection's SSL. Returning 1 = proceed (with whatever cert is on the SSL,
 * which is the ctx's bootstrap cert when we have nothing better); 0 = fail the
 * handshake; <0 = retry (unused). We never fail the handshake just because an
 * SNI has no issued cert — the bootstrap cert lets the connection complete and
 * the client sees a name mismatch, which is the honest state pre-issuance.
 */
static int
ngx_http_autocert_cert_cb(SSL *ssl_conn, void *arg)
{
    ngx_autocert_serve_ctx_t  *sctx = arg;
    ngx_connection_t          *c;
    ngx_autocert_cert_t       *cert;
    ngx_str_t                  host;
    u_char                     host_buf[256];
    const char                *servername;
    uint32_t                   hash;

    c = ngx_ssl_get_connection(ssl_conn);
    if (c == NULL) {
        return 1;
    }

    servername = SSL_get_servername(ssl_conn, TLSEXT_NAMETYPE_host_name);
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "autocert: cert_cb sni=\"%s\"",
                   servername ? servername : (const char *) "");

    /*
     * M10b tls-alpn-01: our ALPN callback flagged this handshake as the CA's
     * "acme-tls/1" validation connection. Serve the challenge certificate for
     * the SNI instead of the real/bootstrap one. acme-tls/1 mandates SNI; a
     * missing or unknown name leaves nothing valid to present, so fail the
     * handshake rather than leak the bootstrap cert under acme-tls/1.
     */
    if (sctx->alpn_zone != NULL
        && ngx_autocert_alpn_conn_index != -1
        && SSL_get_ex_data(ssl_conn, ngx_autocert_alpn_conn_index) != NULL)
    {
        if (servername == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "autocert: acme-tls/1 handshake without SNI, "
                           "failing");
            return 0;
        }

        host.data = (u_char *) servername;
        host.len = ngx_strlen(servername);

        if (host.len == 0 || host.len > NGX_AUTOCERT_ALPN_DOMAIN_MAX) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "autocert: acme-tls/1 SNI length %uz out of range, "
                           "failing", host.len);
            return 0;
        }
        ngx_strlow(host_buf, host.data, host.len);
        host.data = host_buf;

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "autocert: acme-tls/1 challenge for \"%V\"", &host);

        return ngx_http_autocert_serve_alpn_cert(c, ssl_conn, sctx, &host);
    }

    if (servername == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "autocert: no SNI, keeping bootstrap cert");
        return 1;                         /* no SNI -> keep bootstrap cert */
    }

    host.data = (u_char *) servername;
    host.len = ngx_strlen(servername);

    if (host.len == 0 || host.len > 255) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "autocert: SNI length %uz out of range, "
                       "keeping bootstrap cert", host.len);
        return 1;
    }
    ngx_strlow(host_buf, host.data, host.len);
    host.data = host_buf;

    /*
     * Only serve names this instance is configured to issue for. This bounds
     * the per-worker cache to the (config-sized) name set — an attacker cannot
     * grow worker memory with a flood of random SNI values, and a name with no
     * issued cert is simply left on the bootstrap cert. O(n) over a small set.
     */
    if (sctx->names != NULL) {
        ngx_str_t   *nm = sctx->names->elts;
        ngx_uint_t   i, found = 0;

        for (i = 0; i < sctx->names->nelts; i++) {
            if (nm[i].len == host.len
                && ngx_strncmp(nm[i].data, host.data, host.len) == 0)
            {
                found = 1;
                break;
            }
        }

        if (!found) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "autocert: SNI \"%V\" not configured, keeping "
                           "bootstrap cert", &host);
            return 1;                     /* unconfigured SNI -> bootstrap */
        }
    }

    /*
     * Lazily create the per-worker cache pool on first handshake. Done here
     * (not init_process) so it lands in the worker, and only when an autocert
     * server actually receives a connection.
     */
    if (ngx_autocert_cache_pool == NULL) {
        ngx_autocert_cache_pool = ngx_create_pool(4096, c->log);
        if (ngx_autocert_cache_pool == NULL) {
            return 1;
        }
        ngx_rbtree_init(&ngx_autocert_cache_rbtree,
                        &ngx_autocert_cache_sentinel,
                        ngx_str_rbtree_insert_value);
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "autocert: initialized worker cert cache");
    }

    hash = ngx_crc32_short(host.data, host.len);

    cert = (ngx_autocert_cert_t *)
               ngx_str_rbtree_lookup(&ngx_autocert_cache_rbtree, &host, hash);

    if (cert == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "autocert: cache miss for \"%V\", creating entry",
                       &host);
        cert = ngx_pcalloc(ngx_autocert_cache_pool,
                           sizeof(ngx_autocert_cert_t) + host.len);
        if (cert == NULL) {
            return 1;
        }

        cert->sn.str.data = (u_char *) cert + sizeof(ngx_autocert_cert_t);
        ngx_memcpy(cert->sn.str.data, host.data, host.len);
        cert->sn.str.len = host.len;
        cert->sn.node.key = hash;
        cert->mtime = -1;             /* force first load */

        ngx_rbtree_insert(&ngx_autocert_cache_rbtree, &cert->sn.node);
    }

    /*
     * Reload if the files changed. A transient failure (missing/unreadable/
     * malformed) leaves the previously cached cert intact — we keep serving the
     * last-good cert rather than dropping to the bootstrap one, so a renewal
     * race or a momentary read error doesn't break live TLS.
     */
    (void) ngx_http_autocert_cache_reload(cert, &host, sctx, c->log);

    if (cert->cert == NULL || cert->key == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "autocert: no cached cert for \"%V\", keeping "
                       "bootstrap cert", &host);
        return 1;                         /* nothing issued yet -> bootstrap */
    }

    /*
     * Bind the cached cert/key/chain to THIS connection. A partial bind (cert
     * set, key fails) would hand the client a key that doesn't match the cert,
     * so on ANY install failure fail the handshake (return 0) rather than serve
     * a broken pair. Always set the chain — including an empty one — so a stale
     * intermediate inherited from the ctx never ships with a new leaf.
     */
    if (SSL_use_certificate(ssl_conn, cert->cert) != 1
        || SSL_use_PrivateKey(ssl_conn, cert->key) != 1
        || SSL_set1_chain(ssl_conn, cert->chain) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "autocert: installing certificate for \"%V\" failed",
                      &host);
        return 0;
    }

    return 1;
}


/*
 * Reload the cert files for `host` into `c` when their mtime has advanced. The
 * stat is cheap; we do it at most once per second per name (the `checked`
 * coarse throttle) to keep a connection storm from stat()ing every handshake.
 * On any error the previously cached cert (if any) is left intact.
 */
static ngx_int_t
ngx_http_autocert_cache_reload(ngx_autocert_cert_t *c, ngx_str_t *host,
    ngx_autocert_serve_ctx_t *sctx, ngx_log_t *log)
{
    u_char             chain_path[NGX_MAX_PATH], key_path[NGX_MAX_PATH];
    u_char            *p;
    size_t             base;
    ngx_str_t          chain_pem, key_pem, seg;
    ngx_file_info_t    fi;
    time_t             now;
    BIO               *bio = NULL;
    X509              *leaf = NULL, *x;
    STACK_OF(X509)    *chain = NULL;
    EVP_PKEY          *key = NULL;
    ngx_int_t          rc = NGX_ERROR;
    ngx_pool_t        *tmp;

    /* Reject a host that could escape the store as a path segment. */
    if (host->len == 0
        || host->data[0] == '.'
        || ngx_strlchr(host->data, host->data + host->len, '/') != NULL)
    {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "autocert: unsafe SNI \"%V\" for store lookup", host);
        return NGX_ERROR;
    }

    /*
     * Throttle ALL outcomes (hit, miss, or error) to at most one stat per
     * second per name — including the never-loaded case (mtime == -1) so a
     * connection storm against a not-yet-issued name doesn't stat() every
     * handshake. checked starts at 0; the first call always runs.
     */
    now = ngx_time();
    if (now == c->checked) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "autocert: cert cache check for \"%V\" throttled",
                       host);
        return NGX_OK;                    /* throttled; use what we have */
    }
    c->checked = now;

    /*
     * secure:  <path>/<host>/{fullchain,privkey}.pem
     * certbot: <path>/live/<host>/{fullchain,privkey}.pem
     * (serving needs only fullchain + privkey; certbot's extra cert.pem /
     * chain.pem are written for tool compat but not read here.) Paths are
     * bounded by the configured name set; cap to NGX_MAX_PATH defensively.
     */
    if (sctx->store == NGX_HTTP_AUTOCERT_STORE_CERTBOT) {
        seg.data = (u_char *) "/live";
        seg.len = sizeof("/live") - 1;
    } else {
        ngx_str_null(&seg);
    }

    base = sctx->path.len + seg.len + 1 + host->len;
    if (base + sizeof("/fullchain.pem") > NGX_MAX_PATH) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: store path too long for \"%V\"", host);
        return NGX_ERROR;
    }

    p = ngx_cpymem(chain_path, sctx->path.data, sctx->path.len);
    if (seg.len) {
        p = ngx_cpymem(p, seg.data, seg.len);
    }
    *p++ = '/';
    p = ngx_cpymem(p, host->data, host->len);
    ngx_memcpy(p, "/fullchain.pem", sizeof("/fullchain.pem"));

    p = ngx_cpymem(key_path, sctx->path.data, sctx->path.len);
    if (seg.len) {
        p = ngx_cpymem(p, seg.data, seg.len);
    }
    *p++ = '/';
    p = ngx_cpymem(p, host->data, host->len);
    ngx_memcpy(p, "/privkey.pem", sizeof("/privkey.pem"));

    if (ngx_file_info(chain_path, &fi) == NGX_FILE_ERROR) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, ngx_errno,
                       "autocert: no stored fullchain for \"%V\"", host);
        return NGX_ERROR;                 /* no cert yet -> bootstrap */
    }

    if (c->mtime == ngx_file_mtime(&fi)) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                       "autocert: stored cert for \"%V\" unchanged", host);
        return NGX_OK;                    /* unchanged */
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, log, 0,
                   "autocert: reloading stored cert for \"%V\" mtime:%T",
                   host, ngx_file_mtime(&fi));

    /* Read both PEMs into a scratch pool we destroy before returning. */
    tmp = ngx_create_pool(4096, log);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_autocert_read_file(tmp, chain_path, &chain_pem, NULL) != NGX_OK
        || ngx_http_autocert_read_file(tmp, key_path, &key_pem, NULL) != NGX_OK)
    {
        goto done;
    }

    /* Parse the chain: first cert = leaf, rest = intermediates. */
    bio = BIO_new_mem_buf(chain_pem.data, (int) chain_pem.len);
    if (bio == NULL) {
        goto done;
    }

    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (leaf == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: no leaf cert in \"%s\"", chain_path);
        goto done;
    }

    chain = sk_X509_new_null();
    if (chain == NULL) {
        goto done;
    }

    while ((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_push(chain, x) == 0) {
            X509_free(x);
            goto done;
        }
    }

    /*
     * The loop ends on the first NULL. A clean end-of-data raises
     * PEM_R_NO_START_LINE — tolerate ONLY that; any other error means a
     * malformed intermediate, which must abort the reload (don't silently
     * accept a truncated chain). Then clear the queue either way.
     */
    if (ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: malformed certificate chain in \"%s\"",
                      chain_path);
        ERR_clear_error();
        goto done;
    }
    ERR_clear_error();

    BIO_free(bio);
    bio = BIO_new_mem_buf(key_pem.data, (int) key_pem.len);
    if (bio == NULL) {
        goto done;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: bad private key in \"%s\"", key_path);
        goto done;
    }

    if (X509_check_private_key(leaf, key) != 1) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "autocert: key/cert mismatch for \"%V\"", host);
        goto done;
    }

    /* Commit: free the previous generation, adopt the new one. */
    if (c->cert != NULL) {
        X509_free(c->cert);
    }
    if (c->chain != NULL) {
        sk_X509_pop_free(c->chain, X509_free);
    }
    if (c->key != NULL) {
        EVP_PKEY_free(c->key);
    }

    c->cert = leaf;
    c->chain = chain;
    c->key = key;
    c->mtime = ngx_file_mtime(&fi);

    leaf = NULL;                          /* ownership transferred */
    chain = NULL;
    key = NULL;
    rc = NGX_OK;

    ngx_log_error(NGX_LOG_NOTICE, log, 0,
                  "autocert: loaded certificate for \"%V\"", host);

done:

    if (bio != NULL) {
        BIO_free(bio);
    }
    if (leaf != NULL) {
        X509_free(leaf);
    }
    if (chain != NULL) {
        sk_X509_pop_free(chain, X509_free);
    }
    if (key != NULL) {
        EVP_PKEY_free(key);
    }
    ngx_destroy_pool(tmp);

    return rc;
}


/* Read a whole file into a pool buffer. Optionally returns its mtime. */
static ngx_int_t
ngx_http_autocert_read_file(ngx_pool_t *pool, u_char *path, ngx_str_t *out,
    time_t *mtime)
{
    ngx_fd_t         fd;
    ngx_file_info_t  fi;
    ssize_t          n;
    off_t            fsize;
    size_t           size;
    u_char          *buf;

    fd = ngx_open_file(path, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        return NGX_ERROR;
    }

    if (ngx_fd_info(fd, &fi) == NGX_FILE_ERROR) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    /*
     * Check the wide (off_t) size BEFORE narrowing to size_t — a large-file
     * build could otherwise wrap a huge off_t below the cap. A PEM cert/key
     * over ~1 MB is never legitimate.
     */
    fsize = ngx_file_size(&fi);
    if (fsize <= 0 || fsize > 1024 * 1024) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }
    size = (size_t) fsize;

    buf = ngx_pnalloc(pool, size);
    if (buf == NULL) {
        ngx_close_file(fd);
        return NGX_ERROR;
    }

    n = ngx_read_fd(fd, buf, size);
    ngx_close_file(fd);

    if (n != (ssize_t) size) {
        return NGX_ERROR;
    }

    out->data = buf;
    out->len = size;

    if (mtime != NULL) {
        *mtime = ngx_file_mtime(&fi);
    }

    return NGX_OK;
}


/*
 * ALPN selection callback (M10b). Installed on autocert-enabled SSL_CTXs in
 * place of nginx's. If the client offers "acme-tls/1" — which only an ACME CA's
 * tls-alpn-01 validation client does (RFC 8737) — select it and flag the
 * connection so the cert callback serves the challenge cert. Otherwise delegate
 * to a vendored copy of nginx's normal h2/http negotiation.
 */
static int
ngx_http_autocert_alpn_select(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen, void *arg)
{
    ngx_connection_t          *c;
    unsigned int               i;

    (void) arg;

    /* Walk the length-prefixed protocol list looking for "acme-tls/1". */
    for (i = 0; i < inlen; i += 1 + in[i]) {
        if (in[i] == NGX_AUTOCERT_ACME_TLS_ALPN_LEN
            && i + 1 + NGX_AUTOCERT_ACME_TLS_ALPN_LEN <= inlen
            && ngx_memcmp(&in[i + 1], NGX_AUTOCERT_ACME_TLS_ALPN,
                          NGX_AUTOCERT_ACME_TLS_ALPN_LEN) == 0)
        {
            *out = (const unsigned char *) NGX_AUTOCERT_ACME_TLS_ALPN;
            *outlen = NGX_AUTOCERT_ACME_TLS_ALPN_LEN;

            c = ngx_ssl_get_connection(ssl_conn);
            if (c != NULL) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "autocert: tls-alpn-01 validation handshake");
            }

            if (ngx_autocert_alpn_conn_index != -1) {
                (void) SSL_set_ex_data(ssl_conn,
                                       ngx_autocert_alpn_conn_index,
                                       (void *) 1);
            }

            return SSL_TLSEXT_ERR_OK;
        }
    }

    return ngx_http_autocert_alpn_default(ssl_conn, out, outlen, in, inlen);
}


/*
 * Normal-path ALPN negotiation, VENDORED from nginx's ngx_http_ssl_alpn_select
 * (src/http/modules/ngx_http_ssl_module.c). We own the only ALPN callback slot
 * on an autocert ctx, so non-acme clients must still get nginx's exact h2 / h3
 * / http advertise-and-select behaviour. KEEP IN SYNC with nginx/angie.
 */
static int
ngx_http_autocert_alpn_default(ngx_ssl_conn_t *ssl_conn,
    const unsigned char **out, unsigned char *outlen, const unsigned char *in,
    unsigned int inlen)
{
    unsigned int             srvlen;
    unsigned char           *srv;
#if (NGX_HTTP_V2 || NGX_HTTP_V3)
    ngx_http_connection_t   *hc;
#endif
#if (NGX_HTTP_V2)
    ngx_http_v2_srv_conf_t  *h2scf;
#endif
#if (NGX_HTTP_V3)
    ngx_http_v3_srv_conf_t  *h3scf;
#endif
#if (NGX_HTTP_V2 || NGX_HTTP_V3)
    ngx_connection_t        *c;

    c = ngx_ssl_get_connection(ssl_conn);
    hc = c->data;
#endif

#if (NGX_HTTP_V3)
    if (hc->addr_conf->quic) {

        h3scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v3_module);

        if (h3scf->enable && h3scf->enable_hq) {
            srv = (unsigned char *) NGX_HTTP_V3_ALPN_PROTO
                                    NGX_HTTP_V3_HQ_ALPN_PROTO;
            srvlen = sizeof(NGX_HTTP_V3_ALPN_PROTO NGX_HTTP_V3_HQ_ALPN_PROTO)
                     - 1;

        } else if (h3scf->enable_hq) {
            srv = (unsigned char *) NGX_HTTP_V3_HQ_ALPN_PROTO;
            srvlen = sizeof(NGX_HTTP_V3_HQ_ALPN_PROTO) - 1;

        } else if (h3scf->enable) {
            srv = (unsigned char *) NGX_HTTP_V3_ALPN_PROTO;
            srvlen = sizeof(NGX_HTTP_V3_ALPN_PROTO) - 1;

        } else {
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

    } else
#endif
    {
#if (NGX_HTTP_V2)
        h2scf = ngx_http_get_module_srv_conf(hc->conf_ctx, ngx_http_v2_module);

        if (h2scf->enable || hc->addr_conf->http2) {
            srv = (unsigned char *) NGX_HTTP_V2_ALPN_PROTO
                                    NGX_AUTOCERT_HTTP_ALPN_PROTOS;
            srvlen = sizeof(NGX_HTTP_V2_ALPN_PROTO
                            NGX_AUTOCERT_HTTP_ALPN_PROTOS) - 1;

        } else
#endif
        {
            srv = (unsigned char *) NGX_AUTOCERT_HTTP_ALPN_PROTOS;
            srvlen = sizeof(NGX_AUTOCERT_HTTP_ALPN_PROTOS) - 1;
        }
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen, srv, srvlen,
                              in, inlen)
        != OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    return SSL_TLSEXT_ERR_OK;
}


/*
 * Serve the tls-alpn-01 challenge certificate for `host` on this connection.
 * Look the {cert,key} PEM up in the shared store (filled by the helper), parse
 * them, and bind them to the SSL. Returns 1 to proceed (challenge cert served),
 * 0 to fail the handshake — under acme-tls/1 there is no honest fallback, so any
 * miss or parse/install error fails closed.
 */
static int
ngx_http_autocert_serve_alpn_cert(ngx_connection_t *c, SSL *ssl_conn,
    ngx_autocert_serve_ctx_t *sctx, ngx_str_t *host)
{
    ngx_str_t   cert_pem, key_pem;
    ngx_int_t   rc;
    BIO        *bio = NULL;
    X509       *cert = NULL;
    EVP_PKEY   *key = NULL;
    int         ret = 0;

    rc = ngx_autocert_alpn_get(sctx->alpn_zone, host, c->pool,
                               &cert_pem, &key_pem);
    if (rc != NGX_OK) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "autocert: no tls-alpn-01 challenge cert for \"%V\"",
                      host);
        return 0;
    }

    bio = BIO_new_mem_buf(cert_pem.data, (int) cert_pem.len);
    if (bio == NULL) {
        goto done;
    }

    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (cert == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "autocert: malformed tls-alpn-01 cert for \"%V\"", host);
        goto done;
    }

    BIO_free(bio);
    bio = BIO_new_mem_buf(key_pem.data, (int) key_pem.len);
    if (bio == NULL) {
        goto done;
    }

    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "autocert: bad tls-alpn-01 key for \"%V\"", host);
        goto done;
    }

    /*
     * Bind the challenge cert/key (self-signed: no chain). A partial bind would
     * present a mismatched pair, so any failure fails the handshake. Clear any
     * inherited chain so a stale intermediate never ships with the leaf.
     */
    if (SSL_use_certificate(ssl_conn, cert) != 1
        || SSL_use_PrivateKey(ssl_conn, key) != 1
        || SSL_set1_chain(ssl_conn, NULL) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, c->log, 0,
                      "autocert: installing tls-alpn-01 cert for \"%V\" failed",
                      host);
        goto done;
    }

    ngx_log_error(NGX_LOG_INFO, c->log, 0,
                  "autocert: served tls-alpn-01 challenge cert for \"%V\"",
                  host);
    ret = 1;

done:

    if (bio != NULL) {
        BIO_free(bio);
    }
    if (cert != NULL) {
        X509_free(cert);          /* SSL_use_certificate up-refs on success */
    }
    if (key != NULL) {
        EVP_PKEY_free(key);
    }

    return ret;
}
