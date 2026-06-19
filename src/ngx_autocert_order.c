/*
 * ngx_autocert_order — ACME order + authorization + issuance flow (M6a/M6b).
 * See the header for the contract. A chained state machine over the live
 * account's kid-signed POST primitive (ngx_autocert_account_post) plus one
 * unauthenticated GET for the directory's newOrder URL. Any failure funnels to
 * _finish(NGX_ERROR).
 */

#include "ngx_autocert_order.h"
#include "ngx_autocert_acme.h"
#include "ngx_autocert_json.h"
#include "ngx_autocert_challenge.h"
#include "ngx_autocert_alpn.h"
#include "ngx_http_autocert_crypto.h"
#include "ngx_http_autocert_conf.h"     /* key-type enum mapping */

#include <fcntl.h>
#include <sys/stat.h>


/* Authorization poll: up to ~180 tries, 1s apart. Pebble validates fast, but
 * production CAs can legitimately take longer than the old 30s test budget. */
#define NGX_AUTOCERT_ORDER_POLL_MAX     180
#define NGX_AUTOCERT_ORDER_POLL_DELAY   1000    /* ms */

/* Order (finalize) poll: same budget. */
#define NGX_AUTOCERT_ORDER_FIN_POLL_MAX 180
#define NGX_AUTOCERT_ORDER_FIN_DELAY    1000    /* ms */


static void ngx_autocert_order_directory_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_order_new_order(ngx_autocert_order_t *order);
static void ngx_autocert_order_new_order_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_order_get_authz(ngx_autocert_order_t *order);
static void ngx_autocert_order_authz_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_order_respond(ngx_autocert_order_t *order);
static void ngx_autocert_order_respond_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static void ngx_autocert_order_poll_timer(ngx_event_t *ev);
static void ngx_autocert_order_poll_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_order_finalize(ngx_autocert_order_t *order);
static void ngx_autocert_order_finalize_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static void ngx_autocert_order_poll_order_timer(ngx_event_t *ev);
static void ngx_autocert_order_poll_order_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_order_download(ngx_autocert_order_t *order);
static void ngx_autocert_order_download_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_order_store(ngx_autocert_order_t *order);
static ngx_int_t ngx_autocert_order_domain_safe(ngx_str_t *domain);
static ngx_int_t ngx_autocert_order_domain_identifier_safe(ngx_str_t *domain);
static u_char *ngx_autocert_order_tmp_path(ngx_autocert_order_t *order,
    u_char *path);
static ngx_int_t ngx_autocert_order_write_tmp(ngx_autocert_order_t *order,
    u_char *tmp, ngx_str_t *data, ngx_uint_t mode);
static ngx_int_t ngx_autocert_order_publish_alpn(ngx_autocert_order_t *order);
static void ngx_autocert_order_unpublish(ngx_autocert_order_t *order);
static void ngx_autocert_order_finish(ngx_autocert_order_t *order,
    ngx_int_t rc);
static void ngx_autocert_order_note_retry_after(ngx_autocert_order_t *order,
    ngx_autocert_acme_request_t *req);
static ngx_int_t ngx_autocert_order_dup(ngx_autocert_order_t *order,
    ngx_str_t *dst, ngx_str_t *src);
static ngx_int_t ngx_autocert_order_get(ngx_autocert_order_t *order,
    ngx_str_t *url, ngx_autocert_acme_handler_pt handler);


/* Copy an ngx_str_t into the order pool (the source aliases a per-request pool
 * freed when that request completes). */
static ngx_int_t
ngx_autocert_order_dup(ngx_autocert_order_t *order, ngx_str_t *dst,
    ngx_str_t *src)
{
    dst->data = ngx_pnalloc(order->pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    dst->len = src->len;
    return NGX_OK;
}


/*
 * Validate a CA-supplied challenge token before it is used as the http-01
 * challenge-store key, spliced into the key authorization, or fed into the
 * tls-alpn-01 challenge certificate. RFC 8555 §8.3 tokens are base64url
 * (`[A-Za-z0-9_-]`); reject anything else, the empty token, and anything
 * longer than the store accepts. This keeps a hostile/buggy CA from injecting
 * path/control bytes into the :80 handler's match key or unbounded data into
 * cert generation. Returns 1 if safe.
 */
static ngx_uint_t
ngx_autocert_order_token_safe(ngx_str_t *token)
{
    size_t  i;
    u_char  c;

    if (token->len == 0 || token->len > NGX_AUTOCERT_TOKEN_MAX) {
        return 0;
    }

    for (i = 0; i < token->len; i++) {
        c = token->data[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_'))
        {
            return 0;
        }
    }

    return 1;
}


/*
 * Inspect a completed ACME response for an HTTP 429 (rate limited) and, if so,
 * stamp order->retry_after with the absolute time before which this name must
 * not be retried. RFC 7231 Retry-After is either delta-seconds or an HTTP-date;
 * we honour both. A 429 with no/unparsable Retry-After falls back to a 60s hold
 * so a rate-limited CA is never hammered. Called at the top of every response
 * handler (must run before req->pool is destroyed — the header aliases it).
 * Real Let's Encrypt enforces rate limits; honouring Retry-After avoids
 * compounding a block with our own exponential guess.
 */
static void
ngx_autocert_order_note_retry_after(ngx_autocert_order_t *order,
    ngx_autocert_acme_request_t *req)
{
    ngx_str_t  *ra;
    ngx_int_t   secs;
    time_t      when, now;

    /* Cap any honoured Retry-After at a sane maximum: it bounds how long a name
     * is held, keeps ngx_time()+delay clear of time_t overflow for absurd
     * values, and no legitimate ACME rate limit needs longer than a day. */
    enum { RETRY_AFTER_MAX = 24 * 60 * 60 };

    if (req == NULL || req->status != 429) {
        return;
    }

    now = ngx_time();
    ra = ngx_autocert_acme_header(req, "Retry-After");

    if (ra != NULL && ra->len > 0) {
        /* delta-seconds: an unsigned decimal count */
        secs = ngx_atoi(ra->data, ra->len);
        if (secs != NGX_ERROR) {
            if (secs > RETRY_AFTER_MAX) {
                secs = RETRY_AFTER_MAX;
            }
            order->retry_after = now + secs;
            ngx_log_error(NGX_LOG_WARN, order->log, 0,
                          "autocert: rate limited (429) for \"%V\", "
                          "honouring Retry-After %i s", &order->domain, secs);
            return;
        }

        /* HTTP-date form */
        when = ngx_parse_http_time(ra->data, ra->len);
        if (when != NGX_ERROR && when > now) {
            if (when - now > RETRY_AFTER_MAX) {
                when = now + RETRY_AFTER_MAX;
            }
            order->retry_after = when;
            ngx_log_error(NGX_LOG_WARN, order->log, 0,
                          "autocert: rate limited (429) for \"%V\", "
                          "honouring Retry-After until %T", &order->domain,
                          when);
            return;
        }
    }

    /* 429 with no usable hint: hold off 60s rather than retrying immediately. */
    order->retry_after = ngx_time() + 60;
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: 429 with no usable Retry-After for \"%V\"",
                   &order->domain);
    ngx_log_error(NGX_LOG_WARN, order->log, 0,
                  "autocert: rate limited (429) for \"%V\", no usable "
                  "Retry-After; holding 60 s", &order->domain);
}


ngx_int_t
ngx_autocert_order_start(ngx_autocert_order_t *order)
{
    order->done = 0;
    order->challenge_set = 0;
    order->alpn_set = 0;
    order->poll_tries = 0;
    order->order_poll_tries = 0;
    order->retry_after = 0;
    ngx_str_null(&order->order_url);
    ngx_str_null(&order->finalize_url);
    ngx_str_null(&order->new_order_url);
    ngx_str_null(&order->authz_url);
    ngx_str_null(&order->challenge_url);
    ngx_str_null(&order->token);
    ngx_str_null(&order->keyauth);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: order start for \"%V\", challenge %ui",
                   &order->domain, (ngx_uint_t) order->challenge);

    if (order->account == NULL || order->account->kid.len == 0
        || order->domain.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: order start without account/domain");
        return NGX_ERROR;
    }

    if (ngx_autocert_order_domain_identifier_safe(&order->domain) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: refusing unsafe domain identifier \"%V\"",
                      &order->domain);
        return NGX_ERROR;
    }

    order->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, order->log);
    if (order->pool == NULL) {
        return NGX_ERROR;
    }

    /* Step 1: GET the directory to discover the newOrder URL. */
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: GET directory \"%V\"", &order->directory_url);
    if (ngx_autocert_order_get(order, &order->directory_url,
                               ngx_autocert_order_directory_done)
        != NGX_OK)
    {
        ngx_destroy_pool(order->pool);
        order->pool = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Fire an unauthenticated GET on its own request pool. */
static ngx_int_t
ngx_autocert_order_get(ngx_autocert_order_t *order, ngx_str_t *url,
    ngx_autocert_acme_handler_pt handler)
{
    ngx_pool_t                   *pool;
    ngx_autocert_acme_request_t  *req;
    ngx_str_t                     get = ngx_string("GET");

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, order->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    req = ngx_pcalloc(pool, sizeof(ngx_autocert_acme_request_t));
    if (req == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    req->client = order->account->client;
    req->pool = pool;
    req->log = order->log;
    req->method = get;
    req->url = *url;
    req->handler = handler;
    req->data = order;

    if (ngx_autocert_acme_request(req) != NGX_OK) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_autocert_order_directory_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_order_t       *order = req->data;
    ngx_autocert_json_value_t  *root;
    ngx_str_t                   no;
    ngx_int_t                   ok = NGX_ERROR;

    ngx_autocert_order_note_retry_after(order, req);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: directory done rc:%i status:%ui", rc,
                   req->status);

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        if (root != NULL
            && ngx_autocert_json_object_str(root, "newOrder", &no) == NGX_OK
            && ngx_autocert_order_dup(order, &order->new_order_url, &no)
               == NGX_OK)
        {
            ok = NGX_OK;
            ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                           "autocert: discovered newOrder \"%V\"",
                           &order->new_order_url);
        }
    }

    ngx_destroy_pool(req->pool);

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: ACME directory missing newOrder");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    if (ngx_autocert_order_new_order(order) != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
}


/* Step 2: POST newOrder with the single dns identifier. */
static ngx_int_t
ngx_autocert_order_new_order(ngx_autocert_order_t *order)
{
    ngx_str_t  payload;
    u_char    *p;
    size_t     size;

    /* {"identifiers":[{"type":"dns","value":"<domain>"}]} */
    size = sizeof("{\"identifiers\":[{\"type\":\"dns\",\"value\":\"\"}]}") - 1
           + order->domain.len;

    payload.data = ngx_pnalloc(order->pool, size);
    if (payload.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(payload.data,
                   "{\"identifiers\":[{\"type\":\"dns\",\"value\":\"",
                   sizeof("{\"identifiers\":[{\"type\":\"dns\",\"value\":\"")
                       - 1);
    p = ngx_cpymem(p, order->domain.data, order->domain.len);
    p = ngx_cpymem(p, "\"}]}", sizeof("\"}]}") - 1);
    payload.len = p - payload.data;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: POST newOrder for \"%V\" to \"%V\"",
                   &order->domain, &order->new_order_url);

    return ngx_autocert_account_post(order->account, &order->new_order_url,
                                     &payload,
                                     ngx_autocert_order_new_order_done, order);
}


static void
ngx_autocert_order_new_order_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_order_t       *order;
    ngx_autocert_json_value_t  *root, *authzs, *a0;
    ngx_str_t                  *loc, fin, az;
    ngx_int_t                   ok = NGX_ERROR;

    if (req == NULL) {
        /* synthetic error from the POST primitive — order is unreachable here,
         * but the account-side failure already logged; nothing to free. */
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: newOrder done rc:%i status:%ui", rc,
                   req->status);

    /* newOrder replies 201 Created with the order URL in Location. */
    if (rc == NGX_OK && req->status == 201) {
        loc = ngx_autocert_acme_header(req, "Location");
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);

        if (loc != NULL && loc->len > 0 && root != NULL
            && ngx_autocert_json_object_str(root, "finalize", &fin) == NGX_OK)
        {
            authzs = ngx_autocert_json_object_get(root, "authorizations");
            if (authzs != NULL
                && ngx_autocert_json_array_count(authzs) >= 1)
            {
                a0 = ngx_autocert_json_array_item(authzs, 0);
                if (a0 != NULL
                    && a0->type == NGX_AUTOCERT_JSON_STRING
                    && (az = a0->u.string, az.len > 0)   /* reject "" authz URL */
                    && fin.len > 0
                    && ngx_autocert_order_dup(order, &order->order_url, loc)
                       == NGX_OK
                    && ngx_autocert_order_dup(order, &order->finalize_url,
                                              &fin) == NGX_OK
                    && ngx_autocert_order_dup(order, &order->authz_url, &az)
                       == NGX_OK)
                {
                    ok = NGX_OK;
                }
            }
        }
    }

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: newOrder failed, status %ui", req->status);
    }

    ngx_destroy_pool(req->pool);

    if (ok != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    if (ngx_autocert_order_get_authz(order) != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
}


/* Step 3: POST-as-GET the authorization to read its challenges. */
static ngx_int_t
ngx_autocert_order_get_authz(ngx_autocert_order_t *order)
{
    ngx_str_t  empty = ngx_null_string;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: POST-as-GET authz \"%V\"", &order->authz_url);

    return ngx_autocert_account_post(order->account, &order->authz_url, &empty,
                                     ngx_autocert_order_authz_done, order);
}


static void
ngx_autocert_order_authz_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_order_t       *order;
    ngx_autocert_json_value_t  *root, *challenges, *ch;
    ngx_str_t                   thumb, token, type, url, keyauth, chstatus;
    ngx_uint_t                  i, n;
    u_char                     *p;
    ngx_int_t                   ok = NGX_ERROR;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: authz done rc:%i status:%ui", rc, req->status);

    if (rc == NGX_OK && req->status == 200) {
        ngx_str_t  azstatus;

        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);

        /*
         * If the CA already considers this authorization valid (it caches a
         * recent successful validation — common on reissue/renewal), there is
         * no pending challenge to answer: POSTing the challenge would 400.
         * Skip straight to finalize. (RFC 8555 §7.5.1: an order may reuse an
         * existing valid authz.)
         */
        if (root != NULL
            && ngx_autocert_json_object_str(root, "status", &azstatus) == NGX_OK
            && azstatus.len == sizeof("valid") - 1
            && ngx_strncmp(azstatus.data, "valid", azstatus.len) == 0)
        {
            ngx_destroy_pool(req->pool);
            ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                          "autocert: authorization for \"%V\" already valid; "
                          "skipping challenge", &order->domain);
            if (ngx_autocert_order_finalize(order) != NGX_OK) {
                ngx_autocert_order_finish(order, NGX_ERROR);
            }
            return;
        }

        /* The challenge type to answer, per the autocert_challenge directive. */
        ngx_str_t  want;

        if (order->challenge == NGX_AUTOCERT_CHALLENGE_TLS_ALPN_01) {
            ngx_str_set(&want, "tls-alpn-01");
        } else {
            ngx_str_set(&want, "http-01");
        }

        challenges = (root != NULL)
                     ? ngx_autocert_json_object_get(root, "challenges") : NULL;

        if (challenges != NULL) {
            n = ngx_autocert_json_array_count(challenges);
            ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                           "autocert: authz has %ui challenge(s), want \"%V\"",
                           n, &want);

            for (i = 0; i < n; i++) {
                ch = ngx_autocert_json_array_item(challenges, i);
                if (ch == NULL) {
                    continue;
                }
                if (ngx_autocert_json_object_str(ch, "type", &type) != NGX_OK
                    || type.len != want.len
                    || ngx_strncmp(type.data, want.data, want.len) != 0)
                {
                    continue;
                }
                if (ngx_autocert_json_object_str(ch, "status", &chstatus)
                    == NGX_OK)
                {
                    if (chstatus.len != sizeof("pending") - 1
                        || ngx_strncmp(chstatus.data, "pending",
                                       sizeof("pending") - 1) != 0)
                    {
                        continue;
                    }
                }
                if (ngx_autocert_json_object_str(ch, "token", &token) == NGX_OK
                    && ngx_autocert_order_token_safe(&token)
                    && ngx_autocert_json_object_str(ch, "url", &url) == NGX_OK
                    && ngx_autocert_order_dup(order, &order->token, &token)
                       == NGX_OK
                    && ngx_autocert_order_dup(order, &order->challenge_url,
                                              &url) == NGX_OK)
                {
                    ok = NGX_OK;
                    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                                   "autocert: selected %V challenge token "
                                   "\"%V\"", &want, &order->token);
                    break;          /* complete usable http-01 challenge */
                }
                /* malformed/unsafe challenge entry — keep scanning for a usable
                 * one (a hostile token never reaches the keyauth/store/cert). */
            }
        }
    }

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: no usable challenge of the configured type in "
                      "authorization (status %ui)", req->status);
        ngx_destroy_pool(req->pool);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    /* keyauth = token "." base64url(SHA-256(account JWK)). */
    if (ngx_http_autocert_jwk_thumbprint(req->pool, order->account->key,
                                         &thumb)
        != NGX_OK)
    {
        ngx_destroy_pool(req->pool);
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: JWK thumbprint failed");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    keyauth.len = order->token.len + 1 + thumb.len;
    keyauth.data = ngx_pnalloc(order->pool, keyauth.len);
    if (keyauth.data == NULL) {
        ngx_destroy_pool(req->pool);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }
    p = ngx_cpymem(keyauth.data, order->token.data, order->token.len);
    *p++ = '.';
    ngx_memcpy(p, thumb.data, thumb.len);
    order->keyauth = keyauth;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: built key authorization for \"%V\", %uz bytes",
                   &order->domain, keyauth.len);

    ngx_destroy_pool(req->pool);

    /*
     * Publish the challenge answer where the worker can serve it:
     *  - tls-alpn-01: a self-signed challenge cert (SAN + acmeIdentifier) in the
     *    ALPN store, served at the handshake on ALPN "acme-tls/1" (M10b);
     *  - http-01: token->keyauth in the token store, served by the :80 handler.
     */
    if (order->challenge == NGX_AUTOCERT_CHALLENGE_TLS_ALPN_01) {
        if (ngx_autocert_order_publish_alpn(order) != NGX_OK) {
            ngx_autocert_order_finish(order, NGX_ERROR);
            return;
        }
    } else {
        if (ngx_autocert_challenge_set(order->challenge_zone, &order->token,
                                       &order->keyauth)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: could not publish challenge token");
            ngx_autocert_order_finish(order, NGX_ERROR);
            return;
        }
        order->challenge_set = 1;
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                       "autocert: published http-01 challenge for \"%V\"",
                       &order->domain);
    }

    if (ngx_autocert_order_respond(order) != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
}


/*
 * M10c: build the tls-alpn-01 challenge certificate for this order's domain and
 * key authorization (RFC 8737) and publish it into the shared ALPN store, where
 * the worker handshake serves it on ALPN "acme-tls/1" (M10b). The challenge cert
 * uses a throwaway key independent of the issuance cert key; both PEMs are
 * copied into the slab store and the local OpenSSL objects freed here.
 */
static ngx_int_t
ngx_autocert_order_publish_alpn(ngx_autocert_order_t *order)
{
    EVP_PKEY    *key;
    X509        *cert;
    ngx_pool_t  *tmp;
    ngx_str_t    cert_pem, key_pem;
    ngx_int_t    rc = NGX_ERROR;

    if (order->alpn_zone == NULL) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: tls-alpn-01 selected but no ALPN store");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: publishing tls-alpn-01 challenge for \"%V\"",
                   &order->domain);

    tmp = ngx_create_pool(4096, order->log);
    if (tmp == NULL) {
        return NGX_ERROR;
    }

    key = ngx_http_autocert_key_generate(order->key_type);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: tls-alpn-01 challenge key generation failed");
        goto done;
    }

    cert = ngx_http_autocert_acme_tls_cert(key, &order->domain, &order->keyauth);
    if (cert == NULL) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: tls-alpn-01 challenge cert build failed");
        goto done_key;
    }

    if (ngx_http_autocert_cert_to_pem(tmp, cert, &cert_pem) != NGX_OK
        || ngx_http_autocert_key_to_pem(tmp, key, &key_pem) != NGX_OK
        || ngx_autocert_alpn_set(order->alpn_zone, &order->domain,
                                 &cert_pem, &key_pem) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: could not publish tls-alpn-01 challenge cert");
        X509_free(cert);
        goto done_key;
    }

    order->alpn_set = 1;
    rc = NGX_OK;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: published tls-alpn-01 challenge for \"%V\"",
                   &order->domain);

    X509_free(cert);

done_key:

    ngx_http_autocert_key_free(key);

done:

    ngx_destroy_pool(tmp);
    return rc;
}


/* Step 4: POST the challenge URL with {} to tell the CA we are ready. */
static ngx_int_t
ngx_autocert_order_respond(ngx_autocert_order_t *order)
{
    ngx_str_t  payload = ngx_string("{}");

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: POST challenge response \"%V\"",
                   &order->challenge_url);

    return ngx_autocert_account_post(order->account, &order->challenge_url,
                                     &payload,
                                     ngx_autocert_order_respond_done, order);
}


static void
ngx_autocert_order_respond_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_order_t  *order;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: challenge response done rc:%i status:%ui", rc,
                   req->status);

    /* The CA accepts the challenge with 200 and status "pending"/"processing". */
    if (rc != NGX_OK || (req->status != 200 && req->status != 202)) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: challenge respond failed, status %ui",
                      req->status);
        ngx_destroy_pool(req->pool);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_destroy_pool(req->pool);

    /* Step 5: begin polling the authorization for "valid". */
    ngx_memzero(&order->poll_timer, sizeof(ngx_event_t));
    order->poll_timer.handler = ngx_autocert_order_poll_timer;
    order->poll_timer.data = order;
    order->poll_timer.log = order->log;
    ngx_add_timer(&order->poll_timer, NGX_AUTOCERT_ORDER_POLL_DELAY);
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: authz poll armed in %M ms",
                   (ngx_msec_t) NGX_AUTOCERT_ORDER_POLL_DELAY);
}


static void
ngx_autocert_order_poll_timer(ngx_event_t *ev)
{
    ngx_autocert_order_t  *order = ev->data;
    ngx_str_t              empty = ngx_null_string;

    if (++order->poll_tries > NGX_AUTOCERT_ORDER_POLL_MAX) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: authorization poll timed out");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: authz poll try %ui for \"%V\"",
                   order->poll_tries, &order->domain);

    if (ngx_autocert_account_post(order->account, &order->authz_url, &empty,
                                  ngx_autocert_order_poll_done, order)
        != NGX_OK)
    {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
}


static void
ngx_autocert_order_poll_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_order_t       *order;
    ngx_autocert_json_value_t  *root;
    ngx_str_t                   status;
    ngx_uint_t                  valid, pending;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);
    valid = 0;
    pending = 0;

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: authz poll done rc:%i status:%ui", rc,
                   req->status);

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        if (root != NULL
            && ngx_autocert_json_object_str(root, "status", &status) == NGX_OK)
        {
            if (status.len == sizeof("valid") - 1
                && ngx_strncmp(status.data, "valid", status.len) == 0)
            {
                valid = 1;

            } else if ((status.len == sizeof("pending") - 1
                        && ngx_strncmp(status.data, "pending", status.len)
                           == 0)
                       || (status.len == sizeof("processing") - 1
                           && ngx_strncmp(status.data, "processing",
                                          status.len) == 0))
            {
                pending = 1;
            }
            /* anything else (invalid/deactivated/revoked/expired) -> fail */
        }
    }

    ngx_destroy_pool(req->pool);

    if (valid) {
        ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                      "autocert: authorization for \"%V\" is valid",
                      &order->domain);

        /* Step 6: challenge answer no longer needed once validation completed. */
        ngx_autocert_order_unpublish(order);

        /* M6b: finalize the order with a CSR. */
        if (ngx_autocert_order_finalize(order) != NGX_OK) {
            ngx_autocert_order_finish(order, NGX_ERROR);
        }
        return;
    }

    if (!pending) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: authorization did not become valid");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    /* still pending/processing -> poll again after the delay */
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: authz still pending for \"%V\"", &order->domain);
    ngx_add_timer(&order->poll_timer, NGX_AUTOCERT_ORDER_POLL_DELAY);
}


/*
 * M6b step 7: generate a fresh certificate key, build a CSR with SAN=domain,
 * and POST it to the finalize URL. base64url(DER(CSR)) goes in {"csr":…}.
 */
static ngx_int_t
ngx_autocert_order_finalize(ngx_autocert_order_t *order)
{
    ngx_str_t   csr_der, csr_b64, payload;
    u_char     *p;
    ngx_uint_t  curve;

    if (order->finalize_url.len == 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: order has no finalize URL");
        return NGX_ERROR;
    }

    /* key_type enum (P256=0/P384=1) maps 1:1 onto the crypto curve enum. */
    curve = (order->key_type == NGX_HTTP_AUTOCERT_KEY_P384)
            ? NGX_HTTP_AUTOCERT_CRYPTO_P384
            : NGX_HTTP_AUTOCERT_CRYPTO_P256;

    order->cert_key = ngx_http_autocert_key_generate(curve);
    if (order->cert_key == NULL) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: certificate key generation failed");
        return NGX_ERROR;
    }

    /* PEM now (in the order pool) — needed at store time, and the key handle is
     * freed in _free; capturing the PEM up front decouples the two. */
    if (ngx_http_autocert_key_to_pem(order->pool, order->cert_key,
                                     &order->cert_key_pem)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: certificate key PEM failed");
        return NGX_ERROR;
    }

    if (ngx_http_autocert_csr_der(order->pool, order->cert_key, &order->domain,
                                  &csr_der)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: CSR build failed for \"%V\"", &order->domain);
        return NGX_ERROR;
    }

    if (ngx_http_autocert_base64url_encode(order->pool, &csr_der, &csr_b64)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* payload = {"csr":"<b64url>"} */
    payload.len = sizeof("{\"csr\":\"\"}") - 1 + csr_b64.len;
    payload.data = ngx_pnalloc(order->pool, payload.len);
    if (payload.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(payload.data, "{\"csr\":\"", sizeof("{\"csr\":\"") - 1);
    p = ngx_cpymem(p, csr_b64.data, csr_b64.len);
    *p++ = '"';
    *p++ = '}';
    payload.len = p - payload.data;

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: finalize \"%V\" csr_der:%uz csr_b64:%uz",
                   &order->domain, csr_der.len, csr_b64.len);

    return ngx_autocert_account_post(order->account, &order->finalize_url,
                                     &payload,
                                     ngx_autocert_order_finalize_done, order);
}


static void
ngx_autocert_order_finalize_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_order_t  *order;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: finalize done rc:%i status:%ui", rc,
                   req->status);

    /* Finalize returns the order object (200). The order may already be
     * "valid" with a certificate URL, or still "processing" -> poll. */
    if (rc != NGX_OK || req->status != 200) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: finalize failed, status %ui", req->status);
        ngx_destroy_pool(req->pool);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_destroy_pool(req->pool);

    /* Begin polling the order resource for "valid" + certificate URL. */
    ngx_memzero(&order->order_timer, sizeof(ngx_event_t));
    order->order_timer.handler = ngx_autocert_order_poll_order_timer;
    order->order_timer.data = order;
    order->order_timer.log = order->log;
    ngx_add_timer(&order->order_timer, NGX_AUTOCERT_ORDER_FIN_DELAY);
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: order poll armed in %M ms",
                   (ngx_msec_t) NGX_AUTOCERT_ORDER_FIN_DELAY);
}


/* M6b step 8: POST-as-GET the order URL, look for status=valid + certificate. */
static void
ngx_autocert_order_poll_order_timer(ngx_event_t *ev)
{
    ngx_autocert_order_t  *order = ev->data;
    ngx_str_t              empty = ngx_null_string;

    if (++order->order_poll_tries > NGX_AUTOCERT_ORDER_FIN_POLL_MAX) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: order poll timed out");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: order poll try %ui for \"%V\"",
                   order->order_poll_tries, &order->domain);

    if (ngx_autocert_account_post(order->account, &order->order_url, &empty,
                                  ngx_autocert_order_poll_order_done, order)
        != NGX_OK)
    {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
}


static void
ngx_autocert_order_poll_order_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_order_t       *order;
    ngx_autocert_json_value_t  *root;
    ngx_str_t                   status, cert_url;
    ngx_uint_t                  valid, pending;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);
    valid = 0;
    pending = 0;
    ngx_str_null(&cert_url);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: order poll done rc:%i status:%ui", rc,
                   req->status);

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        if (root != NULL
            && ngx_autocert_json_object_str(root, "status", &status) == NGX_OK)
        {
            if (status.len == sizeof("valid") - 1
                && ngx_strncmp(status.data, "valid", status.len) == 0)
            {
                if (ngx_autocert_json_object_str(root, "certificate", &cert_url)
                    == NGX_OK
                    && cert_url.len != 0
                    && ngx_autocert_order_dup(order, &order->cert_url,
                                              &cert_url) == NGX_OK)
                {
                    valid = 1;
                }

            } else if ((status.len == sizeof("pending") - 1
                        && ngx_strncmp(status.data, "pending", status.len)
                           == 0)
                       || (status.len == sizeof("processing") - 1
                           && ngx_strncmp(status.data, "processing",
                                          status.len) == 0)
                       || (status.len == sizeof("ready") - 1
                           && ngx_strncmp(status.data, "ready",
                                          status.len) == 0))
            {
                pending = 1;
            }
            /* "invalid" or anything else -> fail */
        }
    }

    ngx_destroy_pool(req->pool);

    if (valid) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                       "autocert: order valid, certificate URL \"%V\"",
                       &order->cert_url);
        if (ngx_autocert_order_download(order) != NGX_OK) {
            ngx_autocert_order_finish(order, NGX_ERROR);
        }
        return;
    }

    if (!pending) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: order did not become valid");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: order still pending for \"%V\"", &order->domain);
    ngx_add_timer(&order->order_timer, NGX_AUTOCERT_ORDER_FIN_DELAY);
}


/* M6b step 9: POST-as-GET the certificate URL -> PEM chain in the body. */
static ngx_int_t
ngx_autocert_order_download(ngx_autocert_order_t *order)
{
    ngx_str_t  empty = ngx_null_string;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: downloading certificate from \"%V\"",
                   &order->cert_url);

    return ngx_autocert_account_post(order->account, &order->cert_url, &empty,
                                     ngx_autocert_order_download_done, order);
}


static void
ngx_autocert_order_download_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_order_t  *order;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: certificate download done rc:%i status:%ui "
                   "body:%uz", rc, req->status, req->body_out.len);

    if (rc != NGX_OK || req->status != 200 || req->body_out.len == 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: certificate download failed, status %ui",
                      req->status);
        ngx_destroy_pool(req->pool);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    /* Copy the PEM chain into the order pool (req pool is about to die). */
    if (ngx_autocert_order_dup(order, &order->cert_chain, &req->body_out)
        != NGX_OK)
    {
        ngx_destroy_pool(req->pool);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_destroy_pool(req->pool);

    /* M6b step 10: persist to disk. */
    if (ngx_autocert_order_store(order) != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                  "autocert: certificate issued and stored for \"%V\"",
                  &order->domain);
    ngx_autocert_order_finish(order, NGX_OK);
}


/*
 * Reject any domain that could escape store_path when used as a path segment.
 * Upstream name collection already drops empty/leading-dot/wildcard names, but
 * not a configured name containing '/' or a "." / ".." segment, so guard here
 * before it becomes a filesystem path. Only NUL is otherwise unsafe.
 */
static ngx_int_t
ngx_autocert_order_domain_identifier_safe(ngx_str_t *domain)
{
    size_t  i;
    u_char  c;

    if (domain->len == 0 || domain->len > 253
        || domain->data[0] == '.'
        || domain->data[domain->len - 1] == '.')
    {
        return NGX_ERROR;
    }

    for (i = 0; i < domain->len; i++) {
        c = domain->data[i];

        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '.')
        {
            continue;
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_autocert_order_domain_safe(ngx_str_t *domain)
{
    size_t  i;

    if (domain->len == 0) {
        return NGX_ERROR;
    }
    if ((domain->len == 1 && domain->data[0] == '.')
        || (domain->len == 2 && domain->data[0] == '.'
            && domain->data[1] == '.'))
    {
        return NGX_ERROR;
    }
    for (i = 0; i < domain->len; i++) {
        if (domain->data[i] == '/' || domain->data[i] == '\0') {
            return NGX_ERROR;
        }
    }
    return NGX_OK;
}


/* Allocate "<path>.tmp" (NUL-terminated) in the order pool. */
static u_char *
ngx_autocert_order_tmp_path(ngx_autocert_order_t *order, u_char *path)
{
    u_char  *tmp, *p;
    size_t   plen;

    plen = ngx_strlen(path);
    tmp = ngx_pnalloc(order->pool, plen + sizeof(".tmp"));
    if (tmp == NULL) {
        return NULL;
    }
    p = ngx_cpymem(tmp, path, plen);
    ngx_memcpy(p, ".tmp", sizeof(".tmp"));
    return tmp;
}


/*
 * M6b step 10: store the cert key + fullchain under store_path/<domain>/.
 * Secure layout (M7 will add the certbot layout): the per-domain directory is
 * 0700, privkey.pem 0600, fullchain.pem 0644. Both files are written to .tmp
 * siblings (fsync'd), then rename()d back-to-back so a reader never sees a
 * half-written file and the key/chain pair flips as close to atomically as a
 * two-file store allows. On a failure after the key has already been renamed,
 * the new chain temp is left behind (logged) — renewal will redo both.
 */
static ngx_int_t
ngx_autocert_order_store(ngx_autocert_order_t *order)
{
    u_char       *dir, *key_path, *chain_path, *key_tmp, *chain_tmp, *p;
    size_t        base;
    struct stat   st;

    if (order->store_path.len == 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: no store path configured");
        return NGX_ERROR;
    }

    if (ngx_autocert_order_domain_safe(&order->domain) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: refusing unsafe domain \"%V\" as a path",
                      &order->domain);
        return NGX_ERROR;
    }

    /* store_path "/" domain "\0" */
    base = order->store_path.len + 1 + order->domain.len + 1;

    dir = ngx_pnalloc(order->pool, base);
    if (dir == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(dir, order->store_path.data, order->store_path.len);
    *p++ = '/';
    p = ngx_cpymem(p, order->domain.data, order->domain.len);
    *p = '\0';

    if (mkdir((char *) dir, 0700) == -1 && errno != EEXIST) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: mkdir(\"%s\") failed", dir);
        return NGX_ERROR;
    }

    /* The per-domain dir must be a real directory we own, not a symlink an
     * attacker pre-created to redirect the cert/key writes (O_NOFOLLOW only
     * guards the leaf temp file, not the parent dir component). */
    if (lstat((char *) dir, &st) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: lstat(\"%s\") failed", dir);
        return NGX_ERROR;
    }
    if (!S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: store path \"%s\" is not a directory", dir);
        return NGX_ERROR;
    }

    /* dir "/privkey.pem\0" and "/fullchain.pem\0" */
    key_path = ngx_pnalloc(order->pool, base - 1 + sizeof("/privkey.pem"));
    chain_path = ngx_pnalloc(order->pool, base - 1 + sizeof("/fullchain.pem"));
    if (key_path == NULL || chain_path == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(key_path, dir, base - 1);   /* without the NUL */
    ngx_memcpy(p, "/privkey.pem", sizeof("/privkey.pem"));
    p = ngx_cpymem(chain_path, dir, base - 1);
    ngx_memcpy(p, "/fullchain.pem", sizeof("/fullchain.pem"));

    key_tmp = ngx_autocert_order_tmp_path(order, key_path);
    chain_tmp = ngx_autocert_order_tmp_path(order, chain_path);
    if (key_tmp == NULL || chain_tmp == NULL) {
        return NGX_ERROR;
    }

    /* Write + fsync both temps BEFORE either rename, so a write failure leaves
     * the live cert/key untouched. */
    if (ngx_autocert_order_write_tmp(order, key_tmp, &order->cert_key_pem, 0600)
        != NGX_OK)
    {
        return NGX_ERROR;
    }
    if (ngx_autocert_order_write_tmp(order, chain_tmp, &order->cert_chain, 0644)
        != NGX_OK)
    {
        (void) unlink((char *) key_tmp);
        return NGX_ERROR;
    }

    /* Commit. Key first then chain (back-to-back; no I/O between). */
    if (rename((char *) key_tmp, (char *) key_path) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: rename(\"%s\") failed", key_tmp);
        (void) unlink((char *) key_tmp);
        (void) unlink((char *) chain_tmp);
        return NGX_ERROR;
    }
    if (rename((char *) chain_tmp, (char *) chain_path) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: rename(\"%s\") failed (key already committed, "
                      "renewal will reconcile)", chain_tmp);
        (void) unlink((char *) chain_tmp);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/* Write data to an already-built <tmp> path (mode), force perms, fsync, close.
 * Leaves the temp in place for the caller to rename; unlinks it on failure. */
static ngx_int_t
ngx_autocert_order_write_tmp(ngx_autocert_order_t *order, u_char *tmp,
    ngx_str_t *data, ngx_uint_t mode)
{
    int      fd;
    size_t   off;
    ssize_t  n;

    fd = open((char *) tmp,
              O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
              (mode_t) mode);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: open(\"%s\") failed", tmp);
        return NGX_ERROR;
    }

    /* O_CREAT honours umask; force the intended perms regardless. */
    if (fchmod(fd, (mode_t) mode) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: fchmod(\"%s\") failed", tmp);
        (void) close(fd);
        (void) unlink((char *) tmp);
        return NGX_ERROR;
    }

    for (off = 0; off < data->len; off += n) {
        n = write(fd, data->data + off, data->len - off);
        if (n == -1) {
            if (errno == EINTR) {
                n = 0;
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: write(\"%s\") failed", tmp);
            (void) close(fd);
            (void) unlink((char *) tmp);
            return NGX_ERROR;
        }
        if (n == 0) {
            /* zero progress on a non-empty remainder — fail rather than spin. */
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: write(\"%s\") made no progress", tmp);
            (void) close(fd);
            (void) unlink((char *) tmp);
            return NGX_ERROR;
        }
    }

    if (fsync(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: fsync(\"%s\") failed", tmp);
        (void) close(fd);
        (void) unlink((char *) tmp);
        return NGX_ERROR;
    }

    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: close(\"%s\") failed", tmp);
        (void) unlink((char *) tmp);
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Drop whatever challenge answer this order published, from whichever store.
 * Idempotent: clears the flags so repeat calls (finish then free) are no-ops.
 */
static void
ngx_autocert_order_unpublish(ngx_autocert_order_t *order)
{
    if (order->challenge_set && order->challenge_zone != NULL
        && order->token.len != 0)
    {
        (void) ngx_autocert_challenge_remove(order->challenge_zone,
                                             &order->token);
        order->challenge_set = 0;
    }

    if (order->alpn_set && order->alpn_zone != NULL
        && order->domain.len != 0)
    {
        (void) ngx_autocert_alpn_remove(order->alpn_zone, &order->domain);
        order->alpn_set = 0;
    }
}


static void
ngx_autocert_order_finish(ngx_autocert_order_t *order, ngx_int_t rc)
{
    if (order->done) {
        return;
    }
    order->done = 1;

    if (order->poll_timer.timer_set) {
        ngx_del_timer(&order->poll_timer);
    }
    if (order->order_timer.timer_set) {
        ngx_del_timer(&order->order_timer);
    }

    /* Drop the published challenge answer now the authz is settled. It is no
     * longer needed once validation completed (or failed); keeping it serves no
     * purpose and leaks slab. */
    ngx_autocert_order_unpublish(order);

    if (order->handler) {
        order->handler(order, rc);
    }
}


void
ngx_autocert_order_free(ngx_autocert_order_t *order)
{
    ngx_autocert_order_unpublish(order);
    if (order->poll_timer.timer_set) {
        ngx_del_timer(&order->poll_timer);
    }
    if (order->order_timer.timer_set) {
        ngx_del_timer(&order->order_timer);
    }
    if (order->cert_key != NULL) {
        ngx_http_autocert_key_free(order->cert_key);
        order->cert_key = NULL;
    }
    if (order->pool) {
        ngx_destroy_pool(order->pool);
        order->pool = NULL;
    }
}
