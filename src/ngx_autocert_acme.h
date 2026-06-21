/*
 * ngx_autocert_acme — outbound HTTP/1.1-over-TLS client for the ACME helper
 * (M4b).
 *
 * A minimal, single-request-at-a-time HTTPS client that runs entirely on the
 * helper process's nginx event loop: async DNS via ngx_resolver, non-blocking
 * connect via ngx_event_connect_peer, a TLS handshake via ngx_ssl with peer
 * certificate verification, then one HTTP/1.1 request and a buffered response.
 *
 * This is the transport the ACME state machine (M4c+) builds on. M4b proves it
 * by fetching the CA directory document over TLS (Pebble in CI). Only GET is
 * needed for the directory; POST (for newAccount/newOrder, JWS bodies) lands
 * with the ACME flow in later milestones — the request struct already carries a
 * method + body so adding POST is additive.
 *
 * Lifecycle: one ngx_autocert_acme_request_t per in-flight request, allocated
 * from a per-request pool the caller owns. The caller's completion handler is
 * invoked exactly once, on success OR failure; after it returns the request
 * (and its pool) may be destroyed.
 */

#ifndef _NGX_AUTOCERT_ACME_H_INCLUDED_
#define _NGX_AUTOCERT_ACME_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>


/*
 * Shared client context: the TLS config (CA trust store) and the resolver,
 * both built once when the helper starts and reused for every request. Created
 * with ngx_autocert_acme_client_create() and torn down with _client_destroy().
 */
typedef struct {
    ngx_ssl_t        ssl;            /* trust store + client SSL_CTX */
    ngx_resolver_t  *resolver;       /* async DNS (NULL => not configured) */
    ngx_msec_t       resolver_timeout;
    ngx_msec_t       connect_timeout;
    ngx_msec_t       timeout;        /* per-request read/write/handshake */
    ngx_log_t       *log;
} ngx_autocert_acme_client_t;


struct ngx_autocert_acme_request_s;
typedef struct ngx_autocert_acme_request_s  ngx_autocert_acme_request_t;

/*
 * One captured response header, copied into the request pool (NOT aliased into
 * the recv buffer, which may be reallocated as the body streams in). Valid
 * until the request pool is destroyed. value has surrounding linear whitespace
 * trimmed; name keeps its original case but is matched case-insensitively by
 * ngx_autocert_acme_header().
 */
typedef struct {
    ngx_str_t  name;
    ngx_str_t  value;
} ngx_autocert_acme_header_t;

/*
 * Completion callback. rc is NGX_OK if a full HTTP response was read (inspect
 * r->status and r->body), NGX_ERROR on any transport/TLS/resolve failure (a
 * reason is already logged). Invoked exactly once.
 */
typedef void (*ngx_autocert_acme_handler_pt)(ngx_autocert_acme_request_t *r,
    ngx_int_t rc);


struct ngx_autocert_acme_request_s {
    ngx_autocert_acme_client_t   *client;
    ngx_pool_t                   *pool;   /* per-request, caller-owned */
    ngx_log_t                    *log;

    /* request inputs */
    ngx_str_t                     method;   /* "GET" (default) / "POST" */
    ngx_str_t                     url;      /* absolute https:// URL */
    ngx_str_t                     body;     /* POST body, "" for GET */
    ngx_str_t                     content_type;

    /* parsed from url */
    ngx_str_t                     host;     /* for SNI / Host header / verify */
    in_port_t                     port;
    ngx_str_t                     uri;      /* path[?query], at least "/" */

    /* response outputs (valid when handler rc == NGX_OK) */
    ngx_uint_t                    status;   /* HTTP status code */
    ngx_str_t                     body_out; /* response body (pool-allocated) */
    ngx_array_t                  *headers;  /* ngx_autocert_acme_header_t, the
                                             * response headers in order; query
                                             * with ngx_autocert_acme_header() */

    ngx_autocert_acme_handler_pt  handler;
    void                         *data;     /* caller context */

    /* internals */
    ngx_peer_connection_t         peer;
    ngx_resolver_ctx_t           *resolve;
    ngx_buf_t                    *send;
    ngx_buf_t                    *recv;
    ngx_uint_t                    done;     /* handler already fired */

    /* response parse state */
    ngx_uint_t                    headers_done;
    ngx_uint_t                    chunked;         /* Transfer-Encoding: chunked */
    off_t                         content_length;  /* -1 if unknown */
    size_t                        body_offset;     /* start of body in recv */

    /* Incremental chunked-decode validation cursor (avoids re-walking the whole
     * accumulated body on every read — that would be O(N^2)). dechunk_pos is the
     * offset into recv (from b->start) up to which framing is already validated;
     * dechunk_total is the decoded byte count accumulated so far. Both advance
     * only over fully-received chunks, so a partial tail is re-examined next
     * read but already-validated chunks are not. */
    size_t                        dechunk_pos;
    size_t                        dechunk_total;

    /* Absolute deadline (ngx_current_msec scale) for the WHOLE response read.
     * The per-IO read timer resets on every NGX_AGAIN, so on its own it is an
     * inactivity timeout a byte-dripping peer can hold open up to the recv cap;
     * this bounds the total read time. Set when the read phase starts. */
    ngx_msec_t                    read_deadline;
};


/*
 * Build the shared client. trusted_cert is a PEM bundle path used to verify the
 * ACME server (empty => use OpenSSL's default trust store). resolver is the
 * already-built ngx_resolver_t the helper owns (may be NULL, in which case
 * requests fail at resolve with a clear message). Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_autocert_acme_client_create(ngx_autocert_acme_client_t *client,
    ngx_cycle_t *cycle, ngx_str_t *trusted_cert, ngx_resolver_t *resolver,
    ngx_msec_t timeout);

void ngx_autocert_acme_client_destroy(ngx_autocert_acme_client_t *client);


/*
 * Start an async request. r must have client, pool, log, method (or "" => GET),
 * url, handler set; body/content_type for POST. Returns NGX_OK once started
 * (the handler fires later) or NGX_ERROR if it could not even start (bad URL,
 * no resolver) — in the NGX_ERROR case the handler is NOT called.
 *
 * Handler-fires-later guarantee: even when connect AND the TLS handshake both
 * complete synchronously (literal-IP host + immediate connect), the call chain
 * always stops at the response read — the HTTP reply cannot be in the socket
 * buffer before we have returned to the caller, so the first recv yields
 * NGX_AGAIN and unwinds. Thus the handler never fires before this function
 * returns NGX_OK, and callers may safely treat NGX_OK as "pending". See the
 * note at the synchronous ngx_ssl_handshake path in the .c.
 */
ngx_int_t ngx_autocert_acme_request(ngx_autocert_acme_request_t *r);


/*
 * Look up a response header by name (case-insensitive) on a completed request.
 * Returns the (whitespace-trimmed) value, or NULL if absent. If a header
 * appears more than once the first occurrence is returned. Valid only inside
 * the completion handler, before the request pool is destroyed.
 */
ngx_str_t *ngx_autocert_acme_header(ngx_autocert_acme_request_t *r,
    const char *name);


#endif /* _NGX_AUTOCERT_ACME_H_INCLUDED_ */
