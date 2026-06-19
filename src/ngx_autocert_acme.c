/*
 * ngx_autocert_acme — outbound HTTP/1.1-over-TLS client (M4b). See the header
 * for the contract. Flow per request:
 *
 *   parse URL -> resolve host (ngx_resolver) -> ngx_event_connect_peer ->
 *   TLS handshake (ngx_ssl, verify peer) -> write HTTP request -> read +
 *   parse response -> fire handler(NGX_OK) -> caller destroys the pool.
 *
 * Any failure logs a reason and fires handler(NGX_ERROR). The handler runs at
 * most once (guarded by r->done); the request owns no global state, so many
 * could run concurrently, though the ACME flow issues them one at a time.
 */

#include "ngx_autocert_acme.h"


#define NGX_AUTOCERT_RECV_MAX   (256 * 1024)   /* cap a CA response */
#define NGX_AUTOCERT_RECV_INIT  (16 * 1024)


static ngx_int_t ngx_autocert_acme_parse_url(ngx_autocert_acme_request_t *r);
static ngx_int_t ngx_autocert_acme_url_part_safe(ngx_str_t *s);
static void ngx_autocert_acme_resolve_handler(ngx_resolver_ctx_t *ctx);
static ngx_int_t ngx_autocert_acme_connect(ngx_autocert_acme_request_t *r,
    struct sockaddr *sockaddr, socklen_t socklen);
static void ngx_autocert_acme_connect_handler(ngx_event_t *ev);
static ngx_int_t ngx_autocert_acme_ssl_init(ngx_autocert_acme_request_t *r);
static void ngx_autocert_acme_ssl_handshake_handler(ngx_connection_t *c);
static ngx_int_t ngx_autocert_acme_build_request(ngx_autocert_acme_request_t *r);
static void ngx_autocert_acme_write_handler(ngx_event_t *ev);
static void ngx_autocert_acme_read_handler(ngx_event_t *ev);
static ngx_int_t ngx_autocert_acme_parse_response(
    ngx_autocert_acme_request_t *r);
static ngx_int_t ngx_autocert_acme_dechunk(ngx_autocert_acme_request_t *r);
static void ngx_autocert_acme_finalize(ngx_autocert_acme_request_t *r,
    ngx_int_t rc);


ngx_int_t
ngx_autocert_acme_client_create(ngx_autocert_acme_client_t *client,
    ngx_cycle_t *cycle, ngx_str_t *trusted_cert, ngx_resolver_t *resolver,
    ngx_msec_t timeout)
{
    ngx_memzero(&client->ssl, sizeof(ngx_ssl_t));
    client->ssl.log = cycle->log;

    if (ngx_ssl_create(&client->ssl,
                       NGX_SSL_TLSv1_2|NGX_SSL_TLSv1_3, NULL)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "autocert: ngx_ssl_create() failed");
        return NGX_ERROR;
    }

    /*
     * Verify the ACME server's certificate. depth 2 covers a normal
     * leaf+intermediate chain to a trusted root. With an empty trusted_cert we
     * fall back to OpenSSL's default CA store (correct for Let's Encrypt prod);
     * CI passes Pebble's self-signed CA bundle here.
     *
     * ngx_ssl_trusted_certificate() wants an ngx_conf_t (for conf_full_name on
     * the cert path); the helper has none post-config, so build a minimal one
     * over the cycle. It only reads cf->pool / cf->cycle / cf->log.
     */
    {
        ngx_conf_t  cf;

        ngx_memzero(&cf, sizeof(ngx_conf_t));
        cf.cycle = cycle;
        cf.pool = cycle->pool;
        cf.temp_pool = cycle->pool;
        cf.log = cycle->log;

        if (ngx_ssl_trusted_certificate(&cf, &client->ssl, trusted_cert, 2)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "autocert: ngx_ssl_trusted_certificate() failed");
            ngx_ssl_cleanup_ctx(&client->ssl);
            return NGX_ERROR;
        }
    }

    /*
     * ngx_ssl_trusted_certificate() loads the trust store but leaves the verify
     * MODE untouched (it starts as SSL_VERIFY_NONE). Without this the handshake
     * would succeed against ANY peer and SSL_get_verify_result() would return
     * X509_V_OK -- a self-signed impostor with a matching name would pass. Turn
     * on peer verification explicitly. When no custom CA was supplied, also load
     * the system default trust store (ngx_ssl_trusted_certificate with an empty
     * path does not), so verification has roots to chain to (Let's Encrypt prod).
     */
    SSL_CTX_set_verify(client->ssl.ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(client->ssl.ctx, 2);

    if (trusted_cert->len == 0) {
        if (SSL_CTX_set_default_verify_paths(client->ssl.ctx) == 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "autocert: SSL_CTX_set_default_verify_paths() failed");
            ngx_ssl_cleanup_ctx(&client->ssl);
            return NGX_ERROR;
        }
    }

    client->resolver = resolver;
    client->resolver_timeout = 30000;
    client->connect_timeout = timeout;
    client->timeout = timeout;
    client->log = cycle->log;

    return NGX_OK;
}


void
ngx_autocert_acme_client_destroy(ngx_autocert_acme_client_t *client)
{
    if (client->ssl.ctx) {
        ngx_ssl_cleanup_ctx(&client->ssl);
        client->ssl.ctx = NULL;
    }
}


ngx_int_t
ngx_autocert_acme_request(ngx_autocert_acme_request_t *r)
{
    ngx_resolver_ctx_t  *ctx, temp;

    if (r->method.len == 0) {
        ngx_str_set(&r->method, "GET");
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "autocert: request %V \"%V\"", &r->method, &r->url);

    if (ngx_autocert_acme_parse_url(r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: invalid CA URL \"%V\"", &r->url);
        return NGX_ERROR;
    }

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "autocert: parsed URL host %V port %d uri %V",
                   &r->host, (int) r->port, &r->uri);

    if (r->client->resolver == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: no resolver configured (set autocert_resolver) "
                      "- cannot reach the ACME server \"%V\"", &r->host);
        return NGX_ERROR;
    }

    r->content_length = -1;

    /*
     * A literal IP host needs no DNS; ngx_parse_addr fast-paths it. Otherwise
     * start an async resolve; the handler continues to connect.
     */
    {
        ngx_addr_t  addr;

        if (ngx_parse_addr(r->pool, &addr, r->host.data, r->host.len)
            == NGX_OK)
        {
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                           "autocert: host %V is a literal IP, skip resolve",
                           &r->host);
            ngx_inet_set_port(addr.sockaddr, r->port);
            return ngx_autocert_acme_connect(r, addr.sockaddr, addr.socklen);
        }
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "autocert: resolving host %V", &r->host);

    temp.name = r->host;

    ctx = ngx_resolve_start(r->client->resolver, &temp);
    if (ctx == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: ngx_resolve_start() failed for \"%V\"",
                      &r->host);
        return NGX_ERROR;
    }

    if (ctx == NGX_NO_RESOLVER) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: no resolver to resolve \"%V\"", &r->host);
        return NGX_ERROR;
    }

    ctx->name = r->host;
    ctx->handler = ngx_autocert_acme_resolve_handler;
    ctx->data = r;
    ctx->timeout = r->client->resolver_timeout;

    r->resolve = ctx;

    if (ngx_resolve_name(ctx) != NGX_OK) {
        r->resolve = NULL;
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: ngx_resolve_name() failed for \"%V\"",
                      &r->host);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Parse an absolute https:// URL into host/port/uri. Only https is accepted —
 * ACME is TLS-only. IPv6 literals in [..] are supported. Defaults: port 443,
 * uri "/".
 */
static ngx_int_t
ngx_autocert_acme_url_part_safe(ngx_str_t *s)
{
    size_t  i;
    u_char  ch;

    for (i = 0; i < s->len; i++) {
        ch = s->data[i];
        if (ch < 0x21 || ch == 0x7f) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_autocert_acme_parse_url(ngx_autocert_acme_request_t *r)
{
    u_char  *p, *last, *host_start, *host_end, *colon;
    ngx_str_t  scheme = ngx_string("https://");

    if (r->url.len <= scheme.len
        || ngx_strncasecmp(r->url.data, scheme.data, scheme.len) != 0)
    {
        return NGX_ERROR;
    }

    p = r->url.data + scheme.len;
    last = r->url.data + r->url.len;

    if (p >= last) {
        return NGX_ERROR;
    }

    host_start = p;

    if (*p == '[') {
        /* IPv6 literal: host is everything up to and including ']' minus brackets */
        host_start = p + 1;
        host_end = ngx_strlchr(p, last, ']');
        if (host_end == NULL) {
            return NGX_ERROR;
        }
        p = host_end + 1;       /* may point at ':' (port) or '/' or end */
        colon = (p < last && *p == ':') ? p : NULL;

    } else {
        /* host runs until ':' (port) or '/' (path) or end */
        host_end = p;
        while (host_end < last && *host_end != ':' && *host_end != '/') {
            host_end++;
        }
        colon = (host_end < last && *host_end == ':') ? host_end : NULL;
        p = host_end;
    }

    if (host_end <= host_start) {
        return NGX_ERROR;
    }

    r->host.data = host_start;
    r->host.len = host_end - host_start;

    /* port */
    r->port = 443;
    if (colon) {
        u_char     *pe = colon + 1;
        ngx_int_t   n;

        while (pe < last && *pe != '/') {
            pe++;
        }
        if (pe == colon + 1) {
            return NGX_ERROR;
        }
        n = ngx_atoi(colon + 1, pe - (colon + 1));
        if (n == NGX_ERROR || n < 1 || n > 65535) {
            return NGX_ERROR;
        }
        r->port = (in_port_t) n;
        p = pe;
    }

    /* uri = remainder, or "/" */
    if (p < last && *p == '/') {
        r->uri.data = p;
        r->uri.len = last - p;
    } else if (p == last) {
        ngx_str_set(&r->uri, "/");
    } else {
        return NGX_ERROR;
    }

    if (ngx_autocert_acme_url_part_safe(&r->host) != NGX_OK
        || ngx_autocert_acme_url_part_safe(&r->uri) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /*
     * Re-point host at a NUL-terminated pool copy: SSL_set_tlsext_host_name
     * needs a C string, and host as sliced from the URL buffer is not
     * terminated. ngx_ssl_check_host / Host header use the (len,data) form, so
     * the copy serves both.
     */
    {
        u_char  *h = ngx_pnalloc(r->pool, r->host.len + 1);
        if (h == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(h, r->host.data, r->host.len);
        h[r->host.len] = '\0';
        r->host.data = h;
    }

    return NGX_OK;
}


static void
ngx_autocert_acme_resolve_handler(ngx_resolver_ctx_t *ctx)
{
    ngx_autocert_acme_request_t  *r = ctx->data;
    struct sockaddr              *sockaddr;
    socklen_t                     socklen;
    socklen_t                     len;

    if (ctx->state) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: resolve \"%V\" failed: %s",
                      &r->host, ngx_resolver_strerror(ctx->state));
        ngx_resolve_name_done(ctx);
        r->resolve = NULL;
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    /* state==0 means success, for which the resolver guarantees naddrs>=1;
     * guard defensively so a contract violation can't read addrs[0] OOB. */
    if (ctx->naddrs == 0) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: resolve \"%V\" returned no addresses", &r->host);
        ngx_resolve_name_done(ctx);
        r->resolve = NULL;
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "autocert: resolve \"%V\" returned %ui address(es)",
                   &r->host, ctx->naddrs);

    /* Use the first address; copy it out before releasing the resolver ctx. */
    socklen = ctx->addrs[0].socklen;

    sockaddr = ngx_palloc(r->pool, socklen);
    if (sockaddr == NULL) {
        ngx_resolve_name_done(ctx);
        r->resolve = NULL;
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    ngx_memcpy(sockaddr, ctx->addrs[0].sockaddr, socklen);
    ngx_inet_set_port(sockaddr, r->port);
    len = socklen;

    ngx_resolve_name_done(ctx);
    r->resolve = NULL;

    if (ngx_autocert_acme_connect(r, sockaddr, len) != NGX_OK) {
        ngx_autocert_acme_finalize(r, NGX_ERROR);
    }
}


static ngx_int_t
ngx_autocert_acme_connect(ngx_autocert_acme_request_t *r,
    struct sockaddr *sockaddr, socklen_t socklen)
{
    ngx_int_t              rc;
    ngx_connection_t      *c;
    ngx_peer_connection_t *peer = &r->peer;

    peer->sockaddr = sockaddr;
    peer->socklen = socklen;
    peer->name = &r->host;
    peer->get = ngx_event_get_peer;
    peer->log = r->log;
    peer->log_error = NGX_ERROR_ERR;

    rc = ngx_event_connect_peer(peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: connect to \"%V\" failed", &r->host);
        return NGX_ERROR;
    }

    c = peer->connection;
    c->data = r;
    c->pool = r->pool;
    c->log = r->log;
    c->read->log = r->log;
    c->write->log = r->log;

    c->write->handler = ngx_autocert_acme_connect_handler;
    c->read->handler = ngx_autocert_acme_connect_handler;

    if (rc == NGX_AGAIN) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                       "autocert: connect to \"%V\" in progress", &r->host);
        ngx_add_timer(c->write, r->client->connect_timeout);
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, r->log, 0,
                   "autocert: connected to \"%V\", starting TLS", &r->host);

    /*
     * rc == NGX_OK: connected immediately. If TLS setup fails synchronously
     * here (before any event is pending), tear the connection down ourselves
     * and report start-failure: the caller (request/resolve path) destroys the
     * request pool on NGX_ERROR, so no live event handler may reference r after
     * we return. (The async paths finalize instead, which also closes c.)
     */
    if (ngx_autocert_acme_ssl_init(r) != NGX_OK) {
        if (r->peer.connection) {
            ngx_close_connection(r->peer.connection);
            r->peer.connection = NULL;
        }
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_autocert_acme_connect_handler(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_autocert_acme_request_t  *r = c->data;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: connect to \"%V\" timed out", &r->host);
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    /*
     * Confirm the nonblocking connect actually succeeded before starting TLS:
     * a failed connect also wakes the write event, and without this check the
     * failure would be misreported as a TLS error. Mirrors nginx upstream's
     * ngx_event_connect test.
     */
    {
        int        err = 0;
        socklen_t  len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
            err = ngx_socket_errno;
        }
        if (err) {
            ngx_log_error(NGX_LOG_ERR, r->log, err,
                          "autocert: connect to \"%V\" failed", &r->host);
            ngx_autocert_acme_finalize(r, NGX_ERROR);
            return;
        }
    }

    if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    if (ngx_autocert_acme_ssl_init(r) != NGX_OK) {
        ngx_autocert_acme_finalize(r, NGX_ERROR);
    }
}


static ngx_int_t
ngx_autocert_acme_ssl_init(ngx_autocert_acme_request_t *r)
{
    ngx_int_t          rc;
    ngx_connection_t  *c = r->peer.connection;

    if (ngx_ssl_create_connection(&r->client->ssl, c,
                                  NGX_SSL_BUFFER|NGX_SSL_CLIENT)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: ngx_ssl_create_connection() failed");
        return NGX_ERROR;
    }

    /* SNI: required by most ACME front ends (and by Pebble). host is a
     * NUL-terminated pool copy (see parse_url). */
    if (SSL_set_tlsext_host_name(c->ssl->connection, (char *) r->host.data)
        == 0)
    {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: SSL_set_tlsext_host_name(\"%V\") failed",
                      &r->host);
        return NGX_ERROR;
    }

    rc = ngx_ssl_handshake(c);

    if (rc == NGX_AGAIN) {
        ngx_add_timer(c->read, r->client->timeout);
        c->ssl->handler = ngx_autocert_acme_ssl_handshake_handler;
        return NGX_OK;
    }

    ngx_autocert_acme_ssl_handshake_handler(c);
    return NGX_OK;
}


static void
ngx_autocert_acme_ssl_handshake_handler(ngx_connection_t *c)
{
    ngx_autocert_acme_request_t  *r = c->data;
    long                          rc;

    if (c->read->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: TLS handshake to \"%V\" timed out", &r->host);
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    if (!c->ssl->handshaked) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: TLS handshake to \"%V\" failed", &r->host);
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    /* Enforce certificate verification: reject an untrusted ACME server. */
    rc = SSL_get_verify_result(c->ssl->connection);
    if (rc != X509_V_OK) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: ACME server \"%V\" certificate verify failed "
                      "(%l: %s)", &r->host, rc, X509_verify_cert_error_string(rc));
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    if (ngx_ssl_check_host(c, &r->host) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: ACME server \"%V\" certificate name mismatch",
                      &r->host);
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (ngx_autocert_acme_build_request(r) != NGX_OK) {
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    c->write->handler = ngx_autocert_acme_write_handler;
    c->read->handler = ngx_autocert_acme_read_handler;

    ngx_autocert_acme_write_handler(c->write);
}


static ngx_int_t
ngx_autocert_acme_build_request(ngx_autocert_acme_request_t *r)
{
    u_char  *p;
    size_t   len;
    ngx_str_t  ct = r->content_type;

    if (ct.len == 0) {
        ngx_str_set(&ct, "application/jose+json");
    }

    /*
     * Minimal HTTP/1.1: request line, Host, User-Agent, Connection: close,
     * Accept, and for a body Content-Type + Content-Length. We always send
     * Connection: close so the response ends at EOF if no Content-Length.
     */
    /* Host header: include the port when it is not the https default (443),
     * per RFC 7230. ACME servers (e.g. Pebble) derive the directory endpoint
     * URLs from this header, so dropping a non-default port makes every
     * subsequent URL point at :443 and fail to connect. */
    len = r->method.len + 1 + r->uri.len + sizeof(" HTTP/1.1" CRLF) - 1
        + sizeof("Host: ") - 1 + r->host.len
        + (r->port != 443 ? sizeof(":65535") - 1 : 0)
        + sizeof(CRLF) - 1
        + sizeof("User-Agent: ngx-autocert" CRLF) - 1
        + sizeof("Accept: application/json" CRLF) - 1
        + sizeof("Connection: close" CRLF) - 1
        + sizeof(CRLF) - 1;

    if (r->body.len) {
        len += sizeof("Content-Type: ") - 1 + ct.len + sizeof(CRLF) - 1
             + sizeof("Content-Length: ") - 1 + NGX_OFF_T_LEN + sizeof(CRLF) - 1
             + r->body.len;
    }

    r->send = ngx_create_temp_buf(r->pool, len);
    if (r->send == NULL) {
        return NGX_ERROR;
    }

    p = r->send->last;
    p = ngx_cpymem(p, r->method.data, r->method.len);
    *p++ = ' ';
    p = ngx_cpymem(p, r->uri.data, r->uri.len);
    p = ngx_cpymem(p, " HTTP/1.1" CRLF, sizeof(" HTTP/1.1" CRLF) - 1);
    p = ngx_cpymem(p, "Host: ", sizeof("Host: ") - 1);
    p = ngx_cpymem(p, r->host.data, r->host.len);
    if (r->port != 443) {
        p = ngx_sprintf(p, ":%d", (int) r->port);
    }
    p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);
    p = ngx_cpymem(p, "User-Agent: ngx-autocert" CRLF,
                   sizeof("User-Agent: ngx-autocert" CRLF) - 1);
    p = ngx_cpymem(p, "Accept: application/json" CRLF,
                   sizeof("Accept: application/json" CRLF) - 1);
    p = ngx_cpymem(p, "Connection: close" CRLF,
                   sizeof("Connection: close" CRLF) - 1);

    if (r->body.len) {
        p = ngx_cpymem(p, "Content-Type: ", sizeof("Content-Type: ") - 1);
        p = ngx_cpymem(p, ct.data, ct.len);
        p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);
        p = ngx_sprintf(p, "Content-Length: %uz" CRLF, r->body.len);
    }

    p = ngx_cpymem(p, CRLF, sizeof(CRLF) - 1);

    if (r->body.len) {
        p = ngx_cpymem(p, r->body.data, r->body.len);
    }

    r->send->last = p;

    return NGX_OK;
}


static void
ngx_autocert_acme_write_handler(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_autocert_acme_request_t  *r = c->data;
    ssize_t                       n;
    size_t                        size;

    /*
     * The request is fully sent once r->recv is allocated below. A spurious
     * later write event (some event methods keep the write event armed) must
     * not re-enter and clobber the receive buffer / response state.
     */
    if (r->recv != NULL) {
        return;
    }

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: send to \"%V\" timed out", &r->host);
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    while (r->send->pos < r->send->last) {
        size = r->send->last - r->send->pos;

        n = c->send(c, r->send->pos, size);

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, r->client->timeout);
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                ngx_autocert_acme_finalize(r, NGX_ERROR);
            }
            return;
        }

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->log, 0,
                          "autocert: send to \"%V\" failed", &r->host);
            ngx_autocert_acme_finalize(r, NGX_ERROR);
            return;
        }

        r->send->pos += n;
    }

    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

    /* request fully sent; allocate the receive buffer and wait for the reply */
    r->recv = ngx_create_temp_buf(r->pool, NGX_AUTOCERT_RECV_INIT);
    if (r->recv == NULL) {
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    ngx_add_timer(c->read, r->client->timeout);

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    ngx_autocert_acme_read_handler(c->read);
}


static void
ngx_autocert_acme_read_handler(ngx_event_t *ev)
{
    ngx_connection_t             *c = ev->data;
    ngx_autocert_acme_request_t  *r = c->data;
    ssize_t                       n;
    size_t                        avail;
    ngx_buf_t                    *b = r->recv;

    if (ev->timedout) {
        ngx_log_error(NGX_LOG_ERR, r->log, 0,
                      "autocert: read from \"%V\" timed out", &r->host);
        ngx_autocert_acme_finalize(r, NGX_ERROR);
        return;
    }

    for ( ;; ) {

        avail = b->end - b->last;

        if (avail == 0) {
            /* grow the buffer (bounded) */
            size_t      used = b->last - b->start;
            size_t      cap = (b->end - b->start) * 2;
            u_char     *nb;

            if (cap > NGX_AUTOCERT_RECV_MAX) {
                cap = NGX_AUTOCERT_RECV_MAX;
            }
            if (cap <= (size_t) (b->end - b->start)) {
                ngx_log_error(NGX_LOG_ERR, r->log, 0,
                              "autocert: response from \"%V\" too large",
                              &r->host);
                ngx_autocert_acme_finalize(r, NGX_ERROR);
                return;
            }

            nb = ngx_palloc(r->pool, cap);
            if (nb == NULL) {
                ngx_autocert_acme_finalize(r, NGX_ERROR);
                return;
            }
            ngx_memcpy(nb, b->start, used);
            b->start = nb;
            b->pos = nb;
            b->last = nb + used;
            b->end = nb + cap;
            avail = b->end - b->last;
        }

        n = c->recv(c, b->last, avail);

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->read, r->client->timeout);
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_autocert_acme_finalize(r, NGX_ERROR);
            }
            return;
        }

        if (n == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, r->log, 0,
                          "autocert: read from \"%V\" failed", &r->host);
            ngx_autocert_acme_finalize(r, NGX_ERROR);
            return;
        }

        if (n == 0) {
            /* peer closed: response complete if we at least have headers */
            if (!r->headers_done) {
                ngx_log_error(NGX_LOG_ERR, r->log, 0,
                              "autocert: \"%V\" closed before full response",
                              &r->host);
                ngx_autocert_acme_finalize(r, NGX_ERROR);
                return;
            }
            /* A chunked body is only complete when the terminating zero chunk
             * was seen (parse returns NGX_DONE then). EOF before that is a
             * truncated download, not success. */
            if (r->chunked) {
                ngx_log_error(NGX_LOG_ERR, r->log, 0,
                              "autocert: \"%V\" closed before the final chunk",
                              &r->host);
                ngx_autocert_acme_finalize(r, NGX_ERROR);
                return;
            }
            /* If a Content-Length was advertised, EOF before it is satisfied is
             * a truncated response, not success. */
            if (r->content_length >= 0
                && (b->last - b->start) - (off_t) r->body_offset
                   < r->content_length)
            {
                ngx_log_error(NGX_LOG_ERR, r->log, 0,
                              "autocert: \"%V\" closed before full body "
                              "(%O of %O bytes)", &r->host,
                              (off_t) ((b->last - b->start) - r->body_offset),
                              r->content_length);
                ngx_autocert_acme_finalize(r, NGX_ERROR);
                return;
            }

            /* Connection: close framing — EOF marks end of body */
            r->body_out.data = b->start + r->body_offset;
            r->body_out.len = (b->last - b->start) - r->body_offset;
            ngx_autocert_acme_finalize(r, NGX_OK);
            return;
        }

        b->last += n;

        switch (ngx_autocert_acme_parse_response(r)) {
        case NGX_DONE:
            ngx_autocert_acme_finalize(r, NGX_OK);
            return;
        case NGX_ERROR:
            ngx_autocert_acme_finalize(r, NGX_ERROR);
            return;
        default:                /* NGX_AGAIN: read more */
            break;
        }
    }
}


/*
 * Locate the first occurrence of needle in [hay, hay+n) WITHOUT relying on a
 * NUL terminator (the receive buffer is raw socket data, not a C string, so
 * ngx_strstr/ngx_strnstr must not be used on it). Returns NULL if not found.
 */
static u_char *
ngx_autocert_memmem(u_char *hay, size_t n, const char *needle, size_t m)
{
    u_char  *p;

    if (m == 0 || n < m) {
        return NULL;
    }

    for (p = hay; p <= hay + n - m; p++) {
        if (ngx_memcmp(p, needle, m) == 0) {
            return p;
        }
    }

    return NULL;
}


/*
 * Incremental response parse. Returns NGX_DONE when a complete response is
 * available (Content-Length satisfied), NGX_AGAIN to read more, or NGX_ERROR on
 * a malformed response (the caller finalizes; this never finalizes itself, so
 * the read loop never touches freed memory after an error). Minimal: status
 * line (HTTP/1.0|1.1 + 3-digit code), headers (Content-Length interpreted,
 * Transfer-Encoding: chunked decoded), then body by length or de-chunked.
 * Bodies with neither are framed by Connection: close and end at EOF (handled
 * in the read handler).
 */
ngx_str_t *
ngx_autocert_acme_header(ngx_autocert_acme_request_t *r, const char *name)
{
    ngx_autocert_acme_header_t  *h;
    ngx_uint_t                   i;
    size_t                       len;

    if (r->headers == NULL) {
        return NULL;
    }

    len = ngx_strlen(name);
    h = r->headers->elts;

    for (i = 0; i < r->headers->nelts; i++) {
        if (h[i].name.len == len
            && ngx_strncasecmp(h[i].name.data, (u_char *) name, len) == 0)
        {
            return &h[i].value;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_autocert_acme_parse_response(ngx_autocert_acme_request_t *r)
{
    ngx_buf_t  *b = r->recv;
    u_char     *line, *eol, *hdr_end, *limit;
    size_t      total;

    if (!r->headers_done) {
        total = b->last - b->start;

        /* end of headers (CRLFCRLF) */
        hdr_end = ngx_autocert_memmem(b->start, total, CRLF CRLF,
                                      sizeof(CRLF CRLF) - 1);
        if (hdr_end == NULL) {
            return NGX_AGAIN;
        }
        hdr_end += sizeof(CRLF CRLF) - 1;
        r->body_offset = hdr_end - b->start;
        limit = hdr_end - (sizeof(CRLF) - 1);   /* last byte before CRLFCRLF */

        /* status line: "HTTP/1.x SSS ..." */
        eol = ngx_autocert_memmem(b->start, hdr_end - b->start, CRLF,
                                  sizeof(CRLF) - 1);
        if (eol == NULL
            || eol - b->start < (ssize_t) (sizeof("HTTP/1.0 000") - 1)
            || ngx_strncmp(b->start, "HTTP/1.", sizeof("HTTP/1.") - 1) != 0
            || (b->start[7] != '0' && b->start[7] != '1')
            || b->start[8] != ' ')
        {
            ngx_log_error(NGX_LOG_ERR, r->log, 0,
                          "autocert: malformed status line from \"%V\"",
                          &r->host);
            return NGX_ERROR;
        }

        {
            ngx_int_t  code = ngx_atoi(b->start + 9, 3);

            if (code == NGX_ERROR || code < 100 || code > 599) {
                ngx_log_error(NGX_LOG_ERR, r->log, 0,
                              "autocert: bad status code from \"%V\"", &r->host);
                return NGX_ERROR;
            }
            r->status = (ngx_uint_t) code;
        }

        /* scan header lines */
        r->headers = ngx_array_create(r->pool, 8,
                                      sizeof(ngx_autocert_acme_header_t));
        if (r->headers == NULL) {
            return NGX_ERROR;
        }

        line = eol + sizeof(CRLF) - 1;
        while (line < limit) {
            u_char  *colon;

            eol = ngx_autocert_memmem(line, limit - line, CRLF,
                                      sizeof(CRLF) - 1);
            if (eol == NULL) {
                eol = limit;
            }

            /* capture "Name: value" generically (value LWS-trimmed). A line
             * without a colon is malformed; skip it rather than abort. */
            colon = ngx_autocert_memmem(line, eol - line, ":", 1);
            if (colon != NULL && colon > line) {
                ngx_autocert_acme_header_t  *h;
                u_char                      *v = colon + 1, *vend = eol;

                while (v < vend && (*v == ' ' || *v == '\t')) v++;
                while (vend > v && (vend[-1] == ' ' || vend[-1] == '\t')) vend--;

                h = ngx_array_push(r->headers);
                if (h == NULL) {
                    return NGX_ERROR;
                }

                /* Copy into the pool: the recv buffer can be reallocated as the
                 * body streams in (read handler grows it), which would dangle a
                 * pointer aliased into it. */
                h->name.len = colon - line;
                h->name.data = ngx_pnalloc(r->pool, h->name.len);
                h->value.len = vend - v;
                h->value.data = ngx_pnalloc(r->pool, h->value.len);
                if (h->name.data == NULL
                    || (h->value.len && h->value.data == NULL))
                {
                    return NGX_ERROR;
                }
                ngx_memcpy(h->name.data, line, h->name.len);
                ngx_memcpy(h->value.data, v, h->value.len);
            }

            if ((size_t) (eol - line) > sizeof("Content-Length:") - 1
                && ngx_strncasecmp(line, (u_char *) "Content-Length:",
                                   sizeof("Content-Length:") - 1) == 0)
            {
                u_char  *v = line + sizeof("Content-Length:") - 1;
                off_t    cl;

                while (v < eol && (*v == ' ' || *v == '\t')) v++;
                cl = ngx_atoof(v, eol - v);
                if (cl == NGX_ERROR || cl < 0
                    || (r->content_length >= 0 && r->content_length != cl))
                {
                    ngx_log_error(NGX_LOG_ERR, r->log, 0,
                                  "autocert: invalid/conflicting Content-Length "
                                  "from \"%V\"", &r->host);
                    return NGX_ERROR;
                }
                r->content_length = cl;

            } else if ((size_t) (eol - line) > sizeof("Transfer-Encoding:") - 1
                       && ngx_strncasecmp(line,
                                          (u_char *) "Transfer-Encoding:",
                                          sizeof("Transfer-Encoding:") - 1) == 0)
            {
                u_char  *v = line + sizeof("Transfer-Encoding:") - 1;

                while (v < eol && (*v == ' ' || *v == '\t')) v++;

                /* Only "chunked" is supported (some ACME servers — Pebble — use
                 * it for the certificate download). Any other coding is
                 * rejected rather than mis-framed. */
                if ((size_t) (eol - v) == sizeof("chunked") - 1
                    && ngx_strncasecmp(v, (u_char *) "chunked",
                                       sizeof("chunked") - 1) == 0)
                {
                    r->chunked = 1;

                } else {
                    ngx_log_error(NGX_LOG_ERR, r->log, 0,
                                  "autocert: unsupported Transfer-Encoding from "
                                  "\"%V\"", &r->host);
                    return NGX_ERROR;
                }
            }

            line = eol + sizeof(CRLF) - 1;
        }

        if (r->chunked && r->content_length >= 0) {
            ngx_log_error(NGX_LOG_ERR, r->log, 0,
                          "autocert: response from \"%V\" has both "
                          "Transfer-Encoding and Content-Length", &r->host);
            return NGX_ERROR;
        }

        r->headers_done = 1;
    }

    /* chunked transfer-coding (RFC 7230 §4.1): decode the accumulated body. */
    if (r->chunked) {
        return ngx_autocert_acme_dechunk(r);
    }

    /* body by Content-Length */
    if (r->content_length >= 0) {
        off_t  have = (b->last - b->start) - r->body_offset;

        if (have >= r->content_length) {
            r->body_out.data = b->start + r->body_offset;
            r->body_out.len = (size_t) r->content_length;
            return NGX_DONE;
        }
        return NGX_AGAIN;
    }

    /* no Content-Length: wait for EOF (handled in read handler) */
    return NGX_AGAIN;
}


/*
 * Decode a chunked body (RFC 7230 §4.1). Operates on the whole accumulated
 * body region [body_offset, last) each call — cheap for the small ACME cert
 * responses. Returns NGX_DONE once the terminating zero-size chunk is seen
 * (body_out points at a freshly decoded, pool-allocated buffer), NGX_AGAIN if
 * more bytes are needed, or NGX_ERROR on a malformed framing. Chunk extensions
 * and trailers are tolerated/ignored; we do not enforce a maximum but the read
 * buffer growth is already bounded by the client.
 */
static ngx_int_t
ngx_autocert_acme_dechunk(ngx_autocert_acme_request_t *r)
{
    ngx_buf_t  *b = r->recv;
    u_char     *p, *end, *eol, *out, *o;
    size_t      total, size;

    p = b->start + r->body_offset;
    end = b->last;
    total = 0;

    /* First pass: validate framing and sum the decoded size. Bail NGX_AGAIN if
     * we hit the end of what we have mid-chunk. */
    for ( ;; ) {
        eol = ngx_autocert_memmem(p, end - p, CRLF, sizeof(CRLF) - 1);
        if (eol == NULL) {
            return NGX_AGAIN;               /* size line not complete yet */
        }

        /* hex chunk-size, optionally followed by ";ext" */
        {
            u_char  *q = p;
            size = 0;

            if (q == eol) {
                return NGX_ERROR;           /* empty size line */
            }
            for ( ; q < eol; q++) {
                u_char  c = *q;
                int     d;

                if (c >= '0' && c <= '9')      d = c - '0';
                else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
                else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
                else if (c == ';' || c == ' ' || c == '\t') break;  /* ext */
                else return NGX_ERROR;

                if (size > (NGX_MAX_SIZE_T_VALUE >> 4)) {
                    return NGX_ERROR;       /* overflow guard */
                }
                size = (size << 4) | (size_t) d;
            }
        }

        p = eol + sizeof(CRLF) - 1;         /* past the size line */

        if (size == 0) {
            /* last chunk; a trailing CRLF (after optional trailers) ends it. We
             * tolerate trailers: require at least the final CRLF is present. */
            eol = ngx_autocert_memmem(p, end - p, CRLF, sizeof(CRLF) - 1);
            if (eol == NULL) {
                return NGX_AGAIN;
            }
            break;
        }

        /* need size bytes + the trailing CRLF. Compare against the available
         * span without forming size + CRLF (which could wrap for a huge size
         * and let p escape the buffer). */
        if ((size_t) (end - p) < sizeof(CRLF) - 1
            || size > (size_t) (end - p) - (sizeof(CRLF) - 1))
        {
            return NGX_AGAIN;
        }
        total += size;
        p += size;
        if (ngx_memcmp(p, CRLF, sizeof(CRLF) - 1) != 0) {
            return NGX_ERROR;               /* chunk not CRLF-terminated */
        }
        p += sizeof(CRLF) - 1;
    }

    /* Second pass: copy chunk data into a fresh contiguous buffer. */
    out = ngx_pnalloc(r->pool, total ? total : 1);
    if (out == NULL) {
        return NGX_ERROR;
    }
    o = out;
    p = b->start + r->body_offset;
    for ( ;; ) {
        eol = ngx_autocert_memmem(p, end - p, CRLF, sizeof(CRLF) - 1);
        /* eol is guaranteed non-NULL here (validated in pass 1) */
        size = 0;
        {
            u_char  *q;
            for (q = p; q < eol; q++) {
                u_char  c = *q;
                if (c >= '0' && c <= '9')      size = (size << 4) | (c - '0');
                else if (c >= 'a' && c <= 'f') size = (size << 4) | (c-'a'+10);
                else if (c >= 'A' && c <= 'F') size = (size << 4) | (c-'A'+10);
                else break;
            }
        }
        p = eol + sizeof(CRLF) - 1;
        if (size == 0) {
            break;
        }
        o = ngx_cpymem(o, p, size);
        p += size + sizeof(CRLF) - 1;
    }

    r->body_out.data = out;
    r->body_out.len = total;
    return NGX_DONE;
}


static void
ngx_autocert_acme_finalize(ngx_autocert_acme_request_t *r, ngx_int_t rc)
{
    ngx_connection_t  *c;

    if (r->done) {
        return;
    }
    r->done = 1;

    if (r->resolve) {
        ngx_resolve_name_done(r->resolve);
        r->resolve = NULL;
    }

    c = r->peer.connection;
    if (c) {
        if (c->ssl) {
            /* immediate teardown: don't wait for the peer's close_notify and
             * don't block sending ours, so ngx_ssl_shutdown can't return
             * NGX_AGAIN and leave the SSL object alive past pool destruction. */
            c->ssl->no_wait_shutdown = 1;
            c->ssl->no_send_shutdown = 1;
            (void) ngx_ssl_shutdown(c);
        }
        ngx_close_connection(c);
        r->peer.connection = NULL;
    }

    r->handler(r, rc);
}
