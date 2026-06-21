/*
 * ngx_autocert_serve — per-SNI certificate serving at the TLS handshake (M7).
 *
 * Lives in the HTTP module .so. Two halves:
 *
 *  - config time (ngx_http_autocert_serve_init, called from the HTTP module's
 *    postconfiguration): walk every autocert-enabled server, ensure it has a
 *    usable SSL_CTX (building one with a self-signed bootstrap cert when the
 *    operator gave no ssl_certificate), and install an OpenSSL cert_cb that
 *    swaps in the real certificate per-SNI at handshake.
 *
 *  - handshake time (the cert_cb): look the SNI host up in a per-worker cache
 *    keyed by name, (re)load <store>/<host>/{fullchain,privkey}.pem when the
 *    file mtime has changed, and attach it to the connection's SSL. A renewal
 *    therefore takes effect with no config reload (history.md hot-swap
 *    decision) — the next handshake sees the newer mtime and reloads.
 *
 * Why a self-built SSL_CTX instead of injecting a dummy cert before nginx's ssl
 * module runs: ngx_http_ssl_module is a built-in (low module index), so its
 * merge runs before any dynamic module's and it returns before ngx_ssl_create
 * when no ssl_certificate is configured (ctx stays NULL). autocert cannot hook
 * earlier without a core patch, so it builds the ctx itself in postconfig. See
 * history.md 2026-06-18 "M7 cert serving".
 */

#ifndef _NGX_AUTOCERT_SERVE_H_INCLUDED_
#define _NGX_AUTOCERT_SERVE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_autocert_conf.h"


/*
 * Set up per-SNI serving for every autocert-enabled server. Call from the HTTP
 * module's postconfiguration AFTER ngx_http_ssl_module has merged (i.e. it is
 * safe to read sscf->ssl.ctx). Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_http_autocert_serve_init(ngx_conf_t *cf,
    ngx_http_autocert_main_conf_t *amcf);


/*
 * `master_process off` reload: drop the per-worker cert cache + name-index gate
 * so they rebuild from the new config. Call from init_module (single-process
 * path only). No-op-safe before the first handshake builds anything.
 */
void ngx_autocert_serve_reload(void);


#endif /* _NGX_AUTOCERT_SERVE_H_INCLUDED_ */
