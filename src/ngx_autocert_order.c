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
#include "ngx_autocert_shared.h"        /* shared ngx_autocert_renameat2() */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>

/*
 * Atomic two-file commit uses renameat2(RENAME_EXCHANGE) to swap the freshly
 * written per-domain dir with the live one in a single syscall (Linux 3.15+).
 * Called via syscall() so the build does not depend on a glibc renameat2
 * wrapper; an old kernel / unsupporting filesystem returns ENOSYS/EINVAL and we
 * fall back to the sequential rename. RENAME_EXCHANGE may be absent from old
 * UAPI headers, so define it if needed.
 */
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#endif


/*
 * TOCTOU hardening: every store mutation is performed through a directory fd
 * pinned with O_DIRECTORY|O_NOFOLLOW (ngx_autocert_open_dir_path) and *at() syscalls
 * relative to it. Pinning the container inode means an attacker who can swap a
 * path *component* (e.g. replace <store>/live with a symlink between two path
 * lookups) cannot redirect a subsequent mkdir/rename/open: the kernel resolves
 * the leaf against the already-opened inode, not the swapped name. Leaf
 * components are single names (no '/'), so they cannot themselves traverse.
 */

/* ngx_autocert_renameat2() is shared via ngx_autocert_shared.h — the same
 * fd-pinned rename primitive used by the account-key migration in driver.c. */


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
static ngx_int_t ngx_autocert_order_write_tmp_at(ngx_autocert_order_t *order,
    int sfd, const char *leaf, ngx_str_t *data, ngx_uint_t mode);
static ngx_int_t ngx_autocert_order_fsync_dirfd(ngx_autocert_order_t *order,
    int fd, const char *label);
static void ngx_autocert_order_rm_staging_at(int cfd, const char *leaf);
static ngx_int_t ngx_autocert_order_seed_staging_at(ngx_autocert_order_t *order,
    int cfd, const char *dir, int sfd, ngx_uint_t skip_kt);
static ngx_int_t ngx_autocert_order_swap_dirs_at(ngx_autocert_order_t *order,
    int cfd, const char *staging, const char *dir);
static ngx_int_t ngx_autocert_order_publish_alpn(ngx_autocert_order_t *order);
static ngx_int_t ngx_autocert_order_publish_dns(ngx_autocert_order_t *order);
static ngx_int_t ngx_autocert_order_dns_hook(ngx_autocert_order_t *order,
    ngx_str_t *hook, ngx_uint_t is_add);
static void ngx_autocert_order_dns_delay_timer(ngx_event_t *ev);
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
    order->dns_set = 0;
    order->poll_tries = 0;
    order->order_poll_tries = 0;
    order->finalize_retried = 0;
    order->download_retried = 0;
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
        /*
         * Defensive only — not reached in practice. The account POST primitive
         * reserves a non-NULL post_fail_req up front (M9d), so an *async*
         * failure still calls this handler with a real req; a *synchronous*
         * ngx_autocert_account_post() error returns NGX_ERROR to the caller,
         * which finishes the order itself and never invokes this handler. So a
         * NULL req would mean the order is already being torn down elsewhere:
         * we cannot recover the order (it lives in req->data), so just return.
         * The same invariant covers the bare `req == NULL` guards in the other
         * order *_done callbacks below.
         */
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
        } else if (order->challenge == NGX_AUTOCERT_CHALLENGE_DNS_01) {
            ngx_str_set(&want, "dns-01");
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
    } else if (order->challenge == NGX_AUTOCERT_CHALLENGE_DNS_01) {
        /*
         * dns-01 publishes a TXT record out-of-band (an operator exec hook,
         * D3) and must then WAIT for DNS propagation before asking the CA to
         * validate. publish_dns arms the propagation-delay timer, whose handler
         * calls ngx_autocert_order_respond — so do NOT fall through to the
         * synchronous respond below.
         */
        if (ngx_autocert_order_publish_dns(order) != NGX_OK) {
            ngx_autocert_order_finish(order, NGX_ERROR);
        }
        return;
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

    /* Ephemeral tls-alpn-01 challenge cert: always EC, independent of the
     * certificate key type the order will request. */
    key = ngx_http_autocert_key_generate(NGX_HTTP_AUTOCERT_KEY_P384);
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


/* Monotonic clock in ms, for the hook wait deadline (immune to wall-clock
 * jumps and nanosleep oversleep). Returns 0 if the clock read fails. */
static uint64_t
ngx_autocert_dns_monotonic(void)
{
    struct timespec  ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}


static ngx_msec_int_t
ngx_autocert_dns_elapsed_ms(uint64_t start)
{
    return (ngx_msec_int_t) (ngx_autocert_dns_monotonic() - start);
}


/*
 * M16 (D3): run a dns-01 operator hook (publish or remove the TXT record) by
 * fork+execve, argv = { hook, "_acme-challenge.<name>", <txt>, NULL }.
 *
 * The hook inherits the worker's environment by design: operators routinely
 * pass DNS-provider credentials to the hook via environment (certbot-manual
 * convention), so sanitizing it would break the common case. The hook path is
 * an absolute, config-validated path the operator controls, not attacker input.
 *
 * This blocks worker 0 for up to dns_hook_timeout seconds while the hook runs.
 * Hooks are expected to be short (e.g. a curl to a DNS-provider API); the long
 * propagation wait is handled asynchronously by the delay timer, NOT here. Only
 * one order runs at a time, so the brief block is acceptable.
 *
 * Safety: never system()/popen() (no shell, no injection surface); the child
 * closes every inherited descriptor above stderr (the worker's epoll/listen fds
 * are not guaranteed FD_CLOEXEC) and _exit()s — never exit() — on execve
 * failure so no nginx atexit/cleanup handler runs in the half-forked child. The
 * domain and base64url TXT value are validated before they reach the child argv.
 */
static ngx_int_t
ngx_autocert_order_dns_hook(ngx_autocert_order_t *order, ngx_str_t *hook,
    ngx_uint_t is_add)
{
    pid_t             pid, w;
    int               status;
    ngx_int_t         rc;
    ngx_str_t         name;      /* _acme-challenge.<base> */
    ngx_str_t         base;      /* domain with any leading "*." stripped */
    size_t            i;
    u_char           *hook_cstr, *name_cstr, *txt_cstr;
    char             *argv[4];
    ngx_msec_t        timeout_ms;
    uint64_t          start;
    struct timespec   step;
    sigset_t          set, oset;

    extern char     **environ;

    /* A dns-01 identifier may be a wildcard ("*.example.com", D4); the TXT is
     * published at _acme-challenge.<base>, so strip a leading "*." for the name
     * the hook must set. */
    base = order->domain;
    if (base.len >= 2 && base.data[0] == '*' && base.data[1] == '.') {
        base.data += 2;
        base.len -= 2;
    }

    if (ngx_autocert_order_domain_identifier_safe(&base) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: dns-01 refusing to exec hook for unsafe "
                      "domain \"%V\"", &order->domain);
        return NGX_ERROR;
    }

    /* TXT value is base64url(SHA-256(...)) = exactly 43 unpadded chars; reject
     * anything else before it becomes a child argv. */
    if (is_add) {
        if (order->dns_txt_value.len != 43) {
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: dns-01 TXT value has bad length for \"%V\"",
                          &order->domain);
            return NGX_ERROR;
        }
        for (i = 0; i < order->dns_txt_value.len; i++) {
            u_char  c = order->dns_txt_value.data[i];

            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
                  || (c >= '0' && c <= '9') || c == '-' || c == '_'))
            {
                ngx_log_error(NGX_LOG_ERR, order->log, 0,
                              "autocert: dns-01 TXT value not base64url for "
                              "\"%V\"", &order->domain);
                return NGX_ERROR;
            }
        }
    }

    /* Build "_acme-challenge.<base>" and NUL-terminated argv strings in the
     * order pool (execve needs C strings; ngx_str_t are not NUL-terminated). */
    name.len = sizeof("_acme-challenge.") - 1 + base.len;
    name.data = ngx_pnalloc(order->pool, name.len + 1);
    if (name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(ngx_cpymem(name.data, "_acme-challenge.",
                          sizeof("_acme-challenge.") - 1),
               base.data, base.len);
    name.data[name.len] = '\0';
    name_cstr = name.data;

    hook_cstr = ngx_pnalloc(order->pool, hook->len + 1);
    if (hook_cstr == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(hook_cstr, hook->data, hook->len);
    hook_cstr[hook->len] = '\0';

    txt_cstr = ngx_pnalloc(order->pool, order->dns_txt_value.len + 1);
    if (txt_cstr == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(txt_cstr, order->dns_txt_value.data, order->dns_txt_value.len);
    txt_cstr[order->dns_txt_value.len] = '\0';

    argv[0] = (char *) hook_cstr;
    argv[1] = (char *) name_cstr;
    argv[2] = (char *) txt_cstr;
    argv[3] = NULL;

    ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                  "autocert: dns-01 exec %s hook \"%V\" for \"%V\"",
                  is_add ? "add" : "remove", hook, &name);

    /*
     * Block SIGCHLD across the fork+wait. nginx installs a SIGCHLD handler
     * (ngx_signal_handler -> ngx_process_get_status) that reaps ALL children
     * with waitpid(-1); left unblocked it steals our child before this waitpid
     * runs (ECHILD). With it blocked we reap the specific child ourselves; the
     * (now superfluous) signal is delivered harmlessly on restore.
     */
    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    if (sigprocmask(SIG_BLOCK, &set, &oset) != 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: dns-01 sigprocmask() failed");
        return NGX_ERROR;
    }

    rc = NGX_OK;

    pid = fork();
    if (pid < 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: dns-01 fork() failed");
        rc = NGX_ERROR;
        goto unblock;
    }

    if (pid == 0) {
        /* child */
        long  maxfd, fd;

        /* restore the inherited signal mask so the hook runs unblocked */
        (void) sigprocmask(SIG_SETMASK, &oset, NULL);

        /* Own process group so a timeout can kill the whole subtree (the hook
         * plus any children it spawns), not just the direct process. */
        (void) setpgid(0, 0);

        /* Close every inherited fd above stderr so the hook can't touch worker
         * sockets/cert fds. Prefer close_range(2) (Linux 5.9+): one syscall vs.
         * a loop that, with a soft RLIMIT_NOFILE of ~1M on systemd/containers,
         * would otherwise issue ~1M close() calls in the child. Fall back to the
         * bounded loop only when close_range is unavailable. */
#if defined(__linux__) && defined(SYS_close_range)
        if (syscall(SYS_close_range, 3, ~0U, 0) == 0) {
            /* done */
        } else
#endif
        {
            maxfd = sysconf(_SC_OPEN_MAX);
            if (maxfd < 0) {
                maxfd = 1024;
            }
            for (fd = 3; fd < maxfd; fd++) {
                (void) close((int) fd);
            }
        }

        (void) execve((char *) hook_cstr, argv, environ);
        _exit(127);     /* exec failed: _exit, never exit() */
    }

    /*
     * Parent ALSO sets the child's pgid (the canonical double-setpgid): the
     * child runs setpgid(0,0), but if the timeout fires before it does, the
     * later kill(-pid) would hit a non-existent group and the hook would keep
     * running. Setting it here too makes the group exist regardless of which
     * side wins the race. EACCES (child already exec'd) / ESRCH (already gone)
     * are benign.
     */
    (void) setpgid(pid, pid);

    /*
     * Parent: bounded wait. A blocking waitpid() would pin the worker forever
     * on a wedged hook, so poll with WNOHANG against a CLOCK_MONOTONIC deadline
     * (immune to oversleep / EINTR drift) and a short pacing sleep. On timeout
     * SIGKILL the child's whole process group, then reap with a BOUNDED grace
     * loop — if even that does not collect it (child stuck in D state), give up
     * and let nginx's SIGCHLD reaper harvest the zombie after the mask restore,
     * rather than pin the worker on a blocking wait. Clamp the timeout the same
     * way as the propagation delay.
     */
    if (order->dns_hook_timeout <= 0) {
        timeout_ms = 0;
    } else if (order->dns_hook_timeout > 3600) {
        timeout_ms = (ngx_msec_t) 3600 * 1000;
    } else {
        timeout_ms = (ngx_msec_t) order->dns_hook_timeout * 1000;
    }

    step.tv_sec = 0;
    step.tv_nsec = 20 * 1000 * 1000;    /* 20 ms */
    start = ngx_autocert_dns_monotonic();

    for ( ;; ) {
        w = waitpid(pid, &status, WNOHANG);

        if (w == pid) {
            break;
        }
        if (w < 0) {
            if (ngx_errno == EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: dns-01 waitpid() failed");
            rc = NGX_ERROR;
            goto unblock;
        }
        /* w == 0: child still running */
        if (ngx_autocert_dns_elapsed_ms(start) >= (ngx_msec_int_t) timeout_ms) {
            ngx_int_t  grace;

            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: dns-01 hook \"%V\" timed out after %T s, "
                          "killing", hook, order->dns_hook_timeout);
            /* Kill the whole group; if the group kill fails (e.g. the child
             * lost the setpgid race and is still in its own inherited group),
             * fall back to killing the direct child so it never lingers. */
            if (kill(-pid, SIGKILL) != 0) {
                (void) kill(pid, SIGKILL);
            }

            /* bounded grace reap (~1s) so a stuck child can't pin the worker */
            for (grace = 0; grace < 50; grace++) {
                w = waitpid(pid, &status, WNOHANG);
                if (w == pid || (w < 0 && ngx_errno != EINTR)) {
                    break;
                }
                (void) nanosleep(&step, NULL);
            }
            rc = NGX_ERROR;
            goto unblock;
        }
        (void) nanosleep(&step, NULL);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: dns-01 hook \"%V\" failed (%s %d) for \"%V\"",
                      hook,
                      WIFEXITED(status) ? "exit" : "signal",
                      WIFEXITED(status) ? WEXITSTATUS(status)
                                        : WTERMSIG(status),
                      &name);
        rc = NGX_ERROR;
    }

unblock:

    (void) sigprocmask(SIG_SETMASK, &oset, NULL);
    return rc;
}


/*
 * M16: publish the dns-01 challenge. The TXT record value is
 * base64url(SHA-256(keyauth)) (RFC 8555 §8.4), published at
 * _acme-challenge.<domain>. Publishing is out-of-band via an operator exec
 * hook (wired in D3); here in D2 it is a stub that computes + logs the value
 * (tests pre-seed the record). Either way it sets dns_set and arms the
 * propagation-delay timer, whose handler then POSTs the challenge response.
 */
static ngx_int_t
ngx_autocert_order_publish_dns(ngx_autocert_order_t *order)
{
    ngx_msec_t  delay;

    if (ngx_http_autocert_dns01_txt(order->pool, &order->keyauth,
                                    &order->dns_txt_value)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: dns-01 TXT value computation failed for "
                      "\"%V\"", &order->domain);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                  "autocert: dns-01 challenge for \"%V\": publish TXT "
                  "_acme-challenge.%V = \"%V\"",
                  &order->domain, &order->domain, &order->dns_txt_value);

    /*
     * D3: publish the TXT via the operator add-hook. Mark dns_set BEFORE the
     * exec so a later unpublish always runs the remove-hook even if the add
     * partially applied (a half-published record must still be cleaned up). An
     * empty hook keeps the D2 stub behaviour (compute + log only) for the
     * plumbing test; production dns-01 requires the hook (enforced at config).
     */
    order->dns_set = 1;
    if (order->dns_hook_add.len != 0
        && ngx_autocert_order_dns_hook(order, &order->dns_hook_add, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* Wait for DNS propagation before asking the CA to validate. Clamp the
     * seconds→ms conversion so a negative or absurd configured delay can't wrap
     * the time_t multiply (esp. 32-bit time_t) into a tiny/huge ngx_msec_t.
     * A propagation wait beyond an hour is nonsensical, so cap there. */
    if (order->dns_propagation_delay < 0) {
        delay = 0;
    } else if (order->dns_propagation_delay > 3600) {
        delay = (ngx_msec_t) 3600 * 1000;
    } else {
        delay = (ngx_msec_t) order->dns_propagation_delay * 1000;
    }

    ngx_memzero(&order->dns_delay_timer, sizeof(ngx_event_t));
    order->dns_delay_timer.handler = ngx_autocert_order_dns_delay_timer;
    order->dns_delay_timer.data = order;
    order->dns_delay_timer.log = order->log;
    /* cancelable: a pending ACME timer must not pin a gracefully-exiting worker
     * 0 open (which would retain .driver.lock and block driver hand-off on
     * reload). The in-flight order is abandoned on exit — ACME is idempotent, it
     * re-orders next sweep. */
    order->dns_delay_timer.cancelable = 1;
    ngx_add_timer(&order->dns_delay_timer, delay);

    return NGX_OK;
}


/* M16: propagation delay elapsed — POST the challenge response to the CA. */
static void
ngx_autocert_order_dns_delay_timer(ngx_event_t *ev)
{
    ngx_autocert_order_t  *order = ev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, order->log, 0,
                   "autocert: dns-01 propagation wait elapsed for \"%V\", "
                   "responding", &order->domain);

    if (ngx_autocert_order_respond(order) != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
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
        /*
         * A 400 here is recoverable: on a reorder (a renewal sweep, or just
         * ordering the same name twice) the CA reuses a recently-valid
         * authorization (RFC 8555 §7.5.1), so its challenge is no longer
         * "pending" and POSTing it "ready" is rejected. The authz itself may
         * already be valid -- poll it instead of failing the order: poll_done
         * routes valid->finalize, still-pending->keep polling, invalid->fail.
         * Any other outcome (transport error, 5xx, ...) stays terminal.
         */
        if (rc == NGX_OK && req->status == 400) {
            ngx_log_error(NGX_LOG_WARN, order->log, 0,
                          "autocert: challenge respond got 400 for \"%V\"; "
                          "re-polling authorization (likely already valid)",
                          &order->domain);

        } else {
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: challenge respond failed, status %ui",
                          req->status);
            ngx_destroy_pool(req->pool);
            ngx_autocert_order_finish(order, NGX_ERROR);
            return;
        }
    }

    ngx_destroy_pool(req->pool);

    /* Step 5: begin polling the authorization for "valid". */
    ngx_memzero(&order->poll_timer, sizeof(ngx_event_t));
    order->poll_timer.handler = ngx_autocert_order_poll_timer;
    order->poll_timer.data = order;
    order->poll_timer.log = order->log;
    /* cancelable: never pin a gracefully-exiting worker 0 (driver-lock handoff
     * on reload — see audit MED). The bare re-arm in the handler reuses this
     * event, so the flag persists across re-arms. */
    order->poll_timer.cancelable = 1;
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

    /* conf key_type enum and crypto curve enum share identical ordering
     * (P256,P384,RSA2048,RSA3072,RSA4096) — map 1:1 by value. */
    curve = (ngx_uint_t) order->key_type;

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
        /*
         * A 400/403 here is recoverable: the CA flips the authorization to
         * valid asynchronously and the ORDER only transitions pending->ready a
         * moment later (RFC 8555 §7.4). Finalizing before the order is "ready"
         * is rejected, but the order is not dead -- poll it and re-finalize
         * once it reaches "ready" (poll_order_done routes ready->re-finalize,
         * valid->download). Bound it to one such recovery so a CA that keeps
         * 400ing finalize can't loop forever. Any other outcome stays terminal.
         *
         * We recover on any 400/403 rather than only the orderNotReady problem
         * type (avoids parsing the body after its pool is gone): a genuinely
         * terminal 400 (e.g. a bad CSR) is self-correcting here -- the order
         * poll will report "invalid"/never reach "ready", so poll_order_done
         * fails it after at most the bounded poll window, one wasted retry.
         */
        if (rc == NGX_OK && (req->status == 400 || req->status == 403)
            && !order->finalize_retried)
        {
            ngx_log_error(NGX_LOG_WARN, order->log, 0,
                          "autocert: finalize got %ui for \"%V\"; polling order "
                          "until ready, then retrying", req->status,
                          &order->domain);
            ngx_destroy_pool(req->pool);

            ngx_memzero(&order->order_timer, sizeof(ngx_event_t));
            order->order_timer.handler = ngx_autocert_order_poll_order_timer;
            order->order_timer.data = order;
            order->order_timer.log = order->log;
            order->order_timer.cancelable = 1;   /* don't pin exiting worker 0 */
            ngx_add_timer(&order->order_timer, NGX_AUTOCERT_ORDER_FIN_DELAY);
            return;
        }

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
    order->order_timer.cancelable = 1;   /* don't pin exiting worker 0 */
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
    ngx_uint_t                  valid, pending, ready, transient, status_code;

    if (req == NULL) {
        return;
    }

    order = req->data;
    ngx_autocert_order_note_retry_after(order, req);
    valid = 0;
    pending = 0;
    ready = 0;
    status_code = req->status;
    transient = (rc != NGX_OK || req->status != 200);
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

            } else if (status.len == sizeof("ready") - 1
                       && ngx_strncmp(status.data, "ready", status.len) == 0)
            {
                /* The order is ready to be finalized. This is the state a
                 * recovered finalize-400 was waiting for: re-finalize once.
                 * (A first-time finalize never lands here -- finalize moves a
                 * ready order straight to processing/valid -- so "ready" on a
                 * poll means our earlier finalize was too early.) */
                ready = 1;

            } else if ((status.len == sizeof("pending") - 1
                        && ngx_strncmp(status.data, "pending", status.len)
                           == 0)
                       || (status.len == sizeof("processing") - 1
                           && ngx_strncmp(status.data, "processing",
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

    if (ready) {
        /* The order reached "ready" after an early finalize was rejected.
         * Re-finalize exactly once (the flag also gates finalize_done's
         * recovery, so a second rejection is terminal -- no infinite loop). */
        if (order->finalize_retried) {
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: order \"%V\" still 'ready' after a finalize "
                          "retry", &order->domain);
            ngx_autocert_order_finish(order, NGX_ERROR);
            return;
        }
        order->finalize_retried = 1;
        ngx_log_error(NGX_LOG_NOTICE, order->log, 0,
                      "autocert: order \"%V\" now ready, re-finalizing",
                      &order->domain);
        if (ngx_autocert_order_finalize(order) != NGX_OK) {
            ngx_autocert_order_finish(order, NGX_ERROR);
        }
        return;
    }

    if (!pending) {
        /*
         * A transient poll with no usable response (rc != OK or non-200) must
         * not discard a fully issued order: the account layer exhausting its
         * one-shot badNonce retry on this POST-as-GET surfaces here as status 0
         * (a CA 5xx/blip is the same class). The order resource is durable, so
         * re-poll instead of failing. order_poll_tries still caps the total, so
         * a persistently failing CA terminates at the poll timeout rather than
         * looping forever. A real 200 carrying "invalid" is NOT transient and
         * stays terminal below.
         */
        if (transient) {
            ngx_log_error(NGX_LOG_WARN, order->log, 0,
                          "autocert: order poll for \"%V\" got no usable "
                          "response (rc:%i status:%ui); re-polling",
                          &order->domain, rc, status_code);
            ngx_add_timer(&order->order_timer, NGX_AUTOCERT_ORDER_FIN_DELAY);
            return;
        }

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


/*
 * Sanity-check the freshly-downloaded pair before it can overwrite the live
 * cert: the fullchain must parse to at least a leaf X509, any further certs
 * must be well-formed (no truncated/garbage intermediate), and the leaf's
 * public key must match the private key we generated for this order. This is
 * the same contract the serve path enforces at load time (serve.c), pulled
 * forward so a bad CA response is rejected before order_store() commits it.
 * Returns NGX_OK if usable, NGX_ERROR otherwise.
 */
static ngx_int_t
ngx_autocert_order_validate_cert(ngx_autocert_order_t *order)
{
    BIO       *bio;
    X509      *leaf, *x;
    EVP_PKEY  *key;
    ngx_int_t  rc = NGX_ERROR;

    leaf = NULL;
    key = NULL;

    bio = BIO_new_mem_buf(order->cert_chain.data, (int) order->cert_chain.len);
    if (bio == NULL) {
        return NGX_ERROR;
    }

    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (leaf == NULL) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: downloaded chain has no leaf certificate");
        goto done;
    }

    /* Drain the rest of the chain; only a clean end-of-data is acceptable, a
     * malformed intermediate must fail validation (mirrors serve.c). */
    while ((x = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
        X509_free(x);
    }
    if (ERR_GET_REASON(ERR_peek_last_error()) != PEM_R_NO_START_LINE) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: downloaded chain has a malformed certificate");
        ERR_clear_error();
        goto done;
    }
    ERR_clear_error();

    /* Leaf public key must match the private key minted for this order. */
    BIO_free(bio);
    bio = BIO_new_mem_buf(order->cert_key_pem.data,
                          (int) order->cert_key_pem.len);
    if (bio == NULL) {
        goto done;
    }
    key = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: order private key did not parse");
        goto done;
    }
    if (X509_check_private_key(leaf, key) != 1) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: downloaded leaf does not match the order key");
        goto done;
    }

    /* A matching key alone is not sufficient: a trusted-but-buggy CA could
     * sign the CSR key into another DNS name, or return an unusable validity
     * window. Reject it before it can replace the last known-good certificate. */
    if (X509_check_host(leaf, (char *) order->domain.data, order->domain.len,
                        0, NULL) != 1)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: downloaded leaf does not cover \"%V\"",
                      &order->domain);
        goto done;
    }
    if (X509_cmp_current_time(X509_get0_notBefore(leaf)) > 0
        || X509_cmp_current_time(X509_get0_notAfter(leaf)) < 0)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: downloaded leaf for \"%V\" is not currently valid",
                      &order->domain);
        goto done;
    }

    rc = NGX_OK;

done:
    if (key) {
        EVP_PKEY_free(key);
    }
    if (leaf) {
        X509_free(leaf);
    }
    if (bio) {
        BIO_free(bio);
    }
    return rc;
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
        /*
         * A transient download failure is recoverable: the cert URL stays valid
         * (the order is already "valid"), so a single nonce hiccup -- e.g. a
         * second badNonce landing on the account layer's one-shot retry, which
         * surfaces here as a terminal 4xx -- or a brief CA blip should not throw
         * away a fully issued order. Re-poll the order once: poll_order_done sees
         * "valid" and re-drives the download with a fresh nonce. A 200 with an
         * empty/garbage body, or a second failure, stays terminal (the flag also
         * gates against a CA that keeps failing the download forever).
         */
        if (!order->download_retried
            && (rc != NGX_OK || (req->status >= 400 && req->status != 404)))
        {
            order->download_retried = 1;
            ngx_log_error(NGX_LOG_WARN, order->log, 0,
                          "autocert: certificate download got status %ui for "
                          "\"%V\"; re-polling order, then retrying once",
                          req->status, &order->domain);
            ngx_destroy_pool(req->pool);

            /* The order poll counter is shared with the finalize->valid poll
             * that already ran; reset it so the recovery gets the full poll
             * budget (an order that reached valid on the last allowed try would
             * otherwise time out on the very first recovery poll). */
            order->order_poll_tries = 0;

            ngx_memzero(&order->order_timer, sizeof(ngx_event_t));
            order->order_timer.handler = ngx_autocert_order_poll_order_timer;
            order->order_timer.data = order;
            order->order_timer.log = order->log;
            order->order_timer.cancelable = 1;   /* don't pin exiting worker 0 */
            ngx_add_timer(&order->order_timer, NGX_AUTOCERT_ORDER_FIN_DELAY);
            return;
        }

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

    /*
     * Validate the downloaded pair BEFORE it can replace a good on-disk cert.
     * A buggy/malicious ACME server can return a 200 with a body that is not a
     * usable certificate; without this check order_store() would atomically
     * overwrite the live cert with garbage and order_finish(NGX_OK) would clear
     * the renewal backoff, so workers would fail to load on the next reload/
     * restart. Reject here instead: the live cert stays, renewal retries.
     */
    if (ngx_autocert_order_validate_cert(order) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: downloaded certificate for \"%V\" is not usable; "
                      "keeping the existing cert and deferring renewal",
                      &order->domain);
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

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
    size_t  i, start = 0;
    u_char  c;

    if (domain->len == 0 || domain->len > 253) {
        return NGX_ERROR;
    }

    /*
     * D4: a leading-label wildcard "*.rest" is a legal ACME dns identifier.
     * Accept the "*." prefix, then validate the remainder as an ordinary name
     * (no further '*'). The store writer maps "*." to "_wildcard_." so the
     * identifier never reaches the filesystem with a literal '*'.
     */
    if (domain->len >= 2 && domain->data[0] == '*' && domain->data[1] == '.') {
        start = 2;
    }

    if (start >= domain->len                    /* "*." with an empty base */
        || domain->data[start] == '.'           /* leading dot / empty label */
        || domain->data[domain->len - 1] == '.')
    {
        return NGX_ERROR;
    }

    for (i = start; i < domain->len; i++) {
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


/*
 * M6b step 10: store the cert key + fullchain under store_path/<domain>/.
 * Secure layout: the per-domain directory is 0700, privkey.pem 0600,
 * fullchain.pem 0644.
 *
 * The key and chain are a matched PAIR: a reader (the serve path) that ever sees
 * a NEW key beside an OLD chain (or vice versa) gets a key/cert mismatch. To
 * keep the pair consistent across a crash, both PEMs are written + fsync'd into
 * a sibling staging dir "<domain>.tmp/", then committed atomically:
 *   - first issuance (no live dir): rename(2) the staging dir into place;
 *   - renewal (live dir exists): renameat2(RENAME_EXCHANGE) swaps the staging
 *     and live dirs in a single syscall, so the whole pair flips at once.
 * On a kernel/filesystem without RENAME_EXCHANGE we fall back to the old
 * sequential two-file rename (key then chain), which keeps a small mismatch
 * window only there. fsync of the parent dir makes the rename itself durable.
 */
/*
 * Split a fullchain PEM into the leaf (first certificate) and the rest of the
 * chain (intermediates), for the certbot cert.pem / chain.pem files. The leaf
 * is everything up to and including the first END-CERTIFICATE line + its
 * newline; the chain is whatever follows. Returns NGX_ERROR if no certificate
 * boundary is found. A single-cert fullchain yields an empty chain (valid:
 * certbot's chain.pem can be empty for a self-issued/0-intermediate leaf).
 */
static ngx_int_t
ngx_autocert_order_split_chain(ngx_str_t *full, ngx_str_t *leaf, ngx_str_t *rest)
{
    static const u_char  marker[] = "-----END CERTIFICATE-----";
    size_t               mlen = sizeof(marker) - 1;
    size_t               i, off;
    ngx_uint_t           found = 0;

    /* find the first END-CERTIFICATE marker (no cross-TU helper: acme's
     * ngx_autocert_memmem is static to that .so). */
    off = 0;
    if (full->len >= mlen) {
        for (i = 0; i <= full->len - mlen; i++) {   /* len>=mlen: no wrap */
            if (ngx_memcmp(full->data + i, marker, mlen) == 0) {
                off = i + mlen;
                found = 1;
                break;
            }
        }
    }
    if (!found) {
        return NGX_ERROR;
    }

    /* include the trailing newline(s) after the marker in the leaf */
    while (off < full->len
           && (full->data[off] == '\r' || full->data[off] == '\n'))
    {
        off++;
    }

    leaf->data = full->data;
    leaf->len = off;
    rest->data = full->data + off;
    rest->len = full->len - off;
    return NGX_OK;
}


/*
 * Dual-cert storage (Phase B). Each keytype owns its own pair of files inside
 * the shared per-domain <seg> directory so an EC and an RSA cert can coexist:
 *   - EC  (legacy/back-compat names): privkey.pem / fullchain.pem
 *                          + certbot: cert.pem / chain.pem
 *   - RSA:                            privkey.rsa.pem / fullchain.rsa.pem
 *                          + certbot: cert.rsa.pem / chain.rsa.pem
 * The EC names are kept flat (no .ecdsa. suffix) so an existing single-cert
 * store keeps serving without a reissue.
 */
#define ngx_autocert_keytype_is_rsa(kt)                                       \
    ((kt) == NGX_HTTP_AUTOCERT_KEY_RSA2048                                     \
     || (kt) == NGX_HTTP_AUTOCERT_KEY_RSA3072                                  \
     || (kt) == NGX_HTTP_AUTOCERT_KEY_RSA4096)

/*
 * Every file either layout can leave in a <seg> dir, across BOTH keytypes.
 * Used to (a) seed staging from live so the OTHER keytype's files survive the
 * whole-dir swap, and (b) sweep a staging dir clean. Order is irrelevant.
 */
static const char *ngx_autocert_store_files[] = {
    "privkey.pem",      "fullchain.pem",      "cert.pem",      "chain.pem",
    "privkey.rsa.pem",  "fullchain.rsa.pem",  "cert.rsa.pem",  "chain.rsa.pem",
    NULL
};

/* Per-keytype PEM leaf names. priv/chain always; leaf/rest are certbot-only. */
static void
ngx_autocert_keytype_pem_names(ngx_uint_t kt, const char **priv,
    const char **chain, const char **leaf, const char **rest)
{
    if (ngx_autocert_keytype_is_rsa(kt)) {
        *priv  = "privkey.rsa.pem";
        *chain = "fullchain.rsa.pem";
        *leaf  = "cert.rsa.pem";
        *rest  = "chain.rsa.pem";
    } else {
        *priv  = "privkey.pem";
        *chain = "fullchain.pem";
        *leaf  = "cert.pem";
        *rest  = "chain.pem";
    }
}


/*
 * Commit the issued pair into the store. TOCTOU-hardened: a single container
 * directory fd (cfd) is pinned with O_DIRECTORY|O_NOFOLLOW and every mutation
 * (mkdirat / openat / renameat2 / fstatat / unlinkat) is performed relative to
 * it on single-component leaf names. Because the kernel resolves each leaf
 * against the already-opened container inode rather than re-walking the path,
 * an attacker who swaps a path component between two operations cannot redirect
 * a write outside the store. The container is <store_path> (secure layout) or
 * <store_path>/live (certbot layout); both are opened NOFOLLOW so the container
 * itself can never be a planted symlink.
 */
static ngx_int_t
ngx_autocert_order_store(ngx_autocert_order_t *order)
{
    u_char       *cdir, *p;
    u_char        dir[NGX_AUTOCERT_DOMAIN_SEG_MAX + 1];
    u_char        staging[NGX_AUTOCERT_DOMAIN_SEG_MAX + sizeof(".tmp")];
    int           cfd, sfd;
    size_t        clen;
    struct stat   st;
    ngx_int_t     rc, swap;
    ngx_uint_t    certbot;
    ngx_str_t     seg;
    const char   *priv_name, *chain_name, *leaf_name, *rest_name;
    u_char        seg_buf[NGX_AUTOCERT_DOMAIN_SEG_MAX];

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

    /*
     * D4: the on-disk segment maps a wildcard "*.rest" to "_wildcard_.rest"
     * (the literal '*' is not a legal path segment). Non-wildcard names map to
     * themselves. The serve path + driver freshness check use the same mapping
     * (ngx_autocert_fs_segment), so all three agree on the directory.
     */
    seg.data = seg_buf;
    seg.len = ngx_autocert_fs_segment(seg_buf, sizeof(seg_buf), &order->domain);
    if (seg.len == 0) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: store segment too long for \"%V\"",
                      &order->domain);
        return NGX_ERROR;
    }

    /*
     * Container dir path. secure: <store_path>. certbot: <store_path>/live —
     * the per-domain live dirs sit flat under live/ (no archive/ + symlinks).
     * Either way the leaf is <seg> and the staging sibling is "<seg>.tmp".
     */
    certbot = (order->store == NGX_HTTP_AUTOCERT_STORE_CERTBOT);

    clen = order->store_path.len + (certbot ? sizeof("/live") - 1 : 0);
    cdir = ngx_pnalloc(order->pool, clen + 1);
    if (cdir == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(cdir, order->store_path.data, order->store_path.len);
    if (certbot) {
        p = ngx_cpymem(p, "/live", sizeof("/live") - 1);
    }
    *p = '\0';

    /*
     * Pin the container inode. O_NOFOLLOW rejects a planted symlink at the
     * final component; O_DIRECTORY rejects a non-directory. Every store mutation
     * below is *at()-relative to this fd.
     *
     * certbot: <store_path>/live is created (0755) and pinned via mkdirat/openat
     * relative to a freshly-pinned <store_path> fd — never path-based, so a
     * swapped <store_path> component cannot redirect the live/ creation either.
     */
    if (certbot) {
        int      bfd;
        u_char  *base;

        /* NUL-terminated <store_path> (store_path.data may not be). */
        base = ngx_pnalloc(order->pool, order->store_path.len + 1);
        if (base == NULL) {
            return NGX_ERROR;
        }
        p = ngx_cpymem(base, order->store_path.data, order->store_path.len);
        *p = '\0';

        bfd = ngx_autocert_open_dir_path((char *) base, 0, 0);
        if (bfd == -1) {
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: open store dir \"%V\" failed",
                          &order->store_path);
            return NGX_ERROR;
        }
        if (mkdirat(bfd, "live", 0755) == -1 && ngx_errno != NGX_EEXIST) {
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: mkdir(\"%s\") failed", cdir);
            (void) close(bfd);
            return NGX_ERROR;
        }
        cfd = openat(bfd, "live",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        (void) close(bfd);
        if (cfd == -1) {
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: open store dir \"%s\" failed", cdir);
            return NGX_ERROR;
        }

    } else {
        cfd = ngx_autocert_open_dir_path((char *) cdir, 0, 0);
        if (cfd == -1) {
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: open store dir \"%s\" failed", cdir);
            return NGX_ERROR;
        }
    }

    /* Leaf names (single component, no '/'): "<seg>" and "<seg>.tmp". */
    if (seg.len + sizeof(".tmp") > sizeof(staging)) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: store segment too long for \"%V\"",
                      &order->domain);
        (void) close(cfd);
        return NGX_ERROR;
    }
    ngx_memcpy(dir, seg.data, seg.len);
    dir[seg.len] = '\0';
    p = ngx_cpymem(staging, seg.data, seg.len);
    ngx_memcpy(p, ".tmp", sizeof(".tmp"));

    /* Clear any staging dir a previous crash left behind, then create a fresh
     * one we own (0700) relative to the pinned container. */
    ngx_autocert_order_rm_staging_at(cfd, (char *) staging);

    if (mkdirat(cfd, (char *) staging, 0700) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: mkdir(\"%s\") failed", staging);
        (void) close(cfd);
        return NGX_ERROR;
    }

    /* Re-open the staging dir we just made, NOFOLLOW, and verify it is a real
     * directory (defeats a swap of "<seg>.tmp" between mkdirat and this open).
     * All PEM writes go *at()-relative to this staging fd. */
    sfd = openat(cfd, (char *) staging,
                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: open staging \"%s\" failed", staging);
        ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
        (void) close(cfd);
        return NGX_ERROR;
    }
    if (fstat(sfd, &st) == -1 || !S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: staging \"%s\" is not a directory", staging);
        (void) close(sfd);
        ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
        (void) close(cfd);
        return NGX_ERROR;
    }

#define NGX_AUTOCERT_STORE_FAIL()                                            \
    do {                                                                     \
        (void) close(sfd);                                                   \
        ngx_autocert_order_rm_staging_at(cfd, (char *) staging);            \
        (void) close(cfd);                                                   \
        return NGX_ERROR;                                                    \
    } while (0)

    /*
     * Dual-cert: seed staging from the live dir (hardlink) so the OTHER
     * keytype's files survive the whole-<seg> atomic swap below. Must run
     * BEFORE we write this keytype's pair so our writes overwrite the seeded
     * (stale) copy of our own files; the other keytype's files pass through.
     */
    if (ngx_autocert_order_seed_staging_at(order, cfd, (char *) dir, sfd,
                                           order->key_type) != NGX_OK)
    {
        NGX_AUTOCERT_STORE_FAIL();
    }

    ngx_autocert_keytype_pem_names(order->key_type, &priv_name, &chain_name,
                                   &leaf_name, &rest_name);

    /* Write + fsync both PEMs into the staging dir (openat O_NOFOLLOW leaves). */
    if (ngx_autocert_order_write_tmp_at(order, sfd, priv_name,
                                        &order->cert_key_pem, 0600) != NGX_OK)
    {
        NGX_AUTOCERT_STORE_FAIL();
    }
    if (ngx_autocert_order_write_tmp_at(order, sfd, chain_name,
                                        &order->cert_chain, 0644) != NGX_OK)
    {
        NGX_AUTOCERT_STORE_FAIL();
    }

    /*
     * certbot layout also ships cert.pem (the leaf alone) and chain.pem (the
     * intermediates alone) beside privkey.pem + fullchain.pem. Split the
     * downloaded fullchain at the end of the first certificate. (We only SERVE
     * fullchain+privkey; this is purely for certbot-tool compatibility.)
     */
    if (certbot) {
        ngx_str_t  leaf, rest;

        if (ngx_autocert_order_split_chain(&order->cert_chain, &leaf, &rest)
            != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: cannot split fullchain for \"%V\"",
                          &order->domain);
            NGX_AUTOCERT_STORE_FAIL();
        }

        if (ngx_autocert_order_write_tmp_at(order, sfd, leaf_name, &leaf,
                                            0644) != NGX_OK
            || ngx_autocert_order_write_tmp_at(order, sfd, rest_name, &rest,
                                               0644) != NGX_OK)
        {
            NGX_AUTOCERT_STORE_FAIL();
        }
    }

    /* fsync the staging dir so its new entries are durable before the swap. */
    if (ngx_autocert_order_fsync_dirfd(order, sfd, (char *) staging) != NGX_OK) {
        NGX_AUTOCERT_STORE_FAIL();
    }
    (void) close(sfd);
    sfd = -1;

#undef NGX_AUTOCERT_STORE_FAIL

    /* Commit, relative to the pinned container. fstatat NOFOLLOW so a planted
     * symlink at "<seg>" is detected, not followed. */
    if (fstatat(cfd, (char *) dir, &st, AT_SYMLINK_NOFOLLOW) == -1) {

        if (ngx_errno != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: lstat(\"%s\") failed", dir);
            ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
            (void) close(cfd);
            return NGX_ERROR;
        }

        /* First issuance: no live dir -> move staging into place atomically,
         * never replacing an existing entry that raced in (RENAME_NOREPLACE).
         * We do NOT fall back to a plain renameat() when the flag is
         * unsupported: without RENAME_NOREPLACE a destination that raced in
         * after the fstatat would be clobbered. On an old kernel/fs (renameat2
         * is Linux 3.15+) we defer and let renewal retry, same as the
         * RENAME_EXCHANGE-unsupported renewal path. */
        rc = ngx_autocert_renameat2(cfd, (char *) staging, cfd, (char *) dir,
                                    RENAME_NOREPLACE);
        if (rc == NGX_DECLINED) {
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: RENAME_NOREPLACE unsupported; cannot "
                          "atomically commit \"%s\" without risking a clobber; "
                          "deferring", dir);
            ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
            (void) close(cfd);
            return NGX_ERROR;
        }
        if (rc != NGX_OK) {
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: rename(\"%s\" -> \"%s\") failed",
                          staging, dir);
            ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
            (void) close(cfd);
            return NGX_ERROR;
        }
        rc = ngx_autocert_order_fsync_dirfd(order, cfd, (char *) cdir);
        (void) close(cfd);
        return rc;
    }

    /* Live path exists: it must be a real directory, not a file/symlink an
     * attacker planted to redirect writes. */
    if (!S_ISDIR(st.st_mode)) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: store path \"%s\" is not a directory", dir);
        ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
        (void) close(cfd);
        return NGX_ERROR;
    }

    swap = ngx_autocert_order_swap_dirs_at(order, cfd, (char *) staging,
                                           (char *) dir);

    if (swap == NGX_OK) {
        /* staging now holds the OLD pair; drop it. */
        ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
        rc = ngx_autocert_order_fsync_dirfd(order, cfd, (char *) cdir);
        (void) close(cfd);
        return rc;
    }

    ngx_autocert_order_rm_staging_at(cfd, (char *) staging);
    (void) close(cfd);

    if (swap == NGX_ERROR) {
        return NGX_ERROR;
    }

    /*
     * swap == NGX_DECLINED: this filesystem has no RENAME_EXCHANGE, so the
     * live pair cannot be replaced atomically. Rather than do a sequential
     * two-file rename that could leave a mismatched key/chain on a crash, defer:
     * the live cert is left untouched and renewal retries (backoff). First
     * issuance is unaffected -- it has no live dir and commits with a single
     * atomic rename above. This only blocks renewal on exotic stores (network /
     * fuse / overlay fs); a local cert store always supports RENAME_EXCHANGE.
     */
    ngx_log_error(NGX_LOG_ERR, order->log, 0,
                  "autocert: cannot atomically replace \"%s\" (filesystem "
                  "lacks RENAME_EXCHANGE); keeping the existing cert and "
                  "deferring renewal", dir);
    return NGX_ERROR;
}


/* fsync an open directory fd so a preceding rename/create in it is durable.
 * Does not close the fd (caller owns it). */
static ngx_int_t
ngx_autocert_order_fsync_dirfd(ngx_autocert_order_t *order, int fd,
    const char *label)
{
    if (fsync(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: fsync(\"%s\") failed", label);
        return NGX_ERROR;
    }
    return NGX_OK;
}


/*
 * Best-effort removal of the staging dir <leaf> and its known files, all
 * relative to the pinned container dir fd. The staging dir is opened
 * O_NOFOLLOW via openat so a planted symlink at "<leaf>" is never followed:
 * children are unlinked relative to the verified directory fd, and if the entry
 * is itself a symlink / non-directory it is unlinkat'd as a plain entry so the
 * caller's mkdirat can proceed.
 */
static void
ngx_autocert_order_rm_staging_at(int cfd, const char *leaf)
{
    int  fd;

    fd = openat(cfd, leaf, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        if (ngx_errno == NGX_ENOENT) {
            return;                     /* nothing there */
        }
        /* symlink (ELOOP), a file (ENOTDIR), etc. — remove the entry itself,
         * relative to the pinned dir, without following it. */
        (void) unlinkat(cfd, leaf, 0);
        return;
    }

    /* Remove every file either layout / either keytype can leave here: secure
     * has privkey + fullchain; certbot adds cert + chain; RSA adds .rsa.
     * variants of all four. unlinkat on an absent name is a harmless ENOENT, so
     * always try them all (else a leftover file keeps rmdir failing and blocks
     * the next renewal's mkdirat). */
    {
        int  i;
        for (i = 0; ngx_autocert_store_files[i] != NULL; i++) {
            (void) unlinkat(fd, ngx_autocert_store_files[i], 0);
        }
    }
    (void) close(fd);
    (void) unlinkat(cfd, leaf, AT_REMOVEDIR);
}


/*
 * Dual-cert seed-from-live: hardlink every existing file in the live <dir> into
 * the fresh staging dir BEFORE this order overwrites its own keytype's pair.
 *
 * The commit swaps the WHOLE <seg> directory atomically (RENAME_NOREPLACE on
 * first issuance, RENAME_EXCHANGE on renewal). Without seeding, a second
 * keytype's commit would swap in a dir holding ONLY its own pair and destroy
 * the first keytype's cert. Seeding makes staging start as a copy (by hardlink,
 * so no data is rewritten) of the live dir; the caller then overwrites just the
 * two (or four, certbot) files for THIS keytype, leaving the other keytype's
 * files intact. Single-global-order serialization (order != NULL gate) means no
 * concurrent staging races this.
 *
 * CRITICAL: we MUST NOT seed the files THIS keytype is about to (over)write.
 * Seeding hardlinks the live inode into staging; the writer then opens that
 * staging name with O_TRUNC, which would truncate the SHARED inode — destroying
 * the live cert before the atomic swap. So skip_kt's four names are excluded;
 * only the OTHER keytype's files are carried forward (their inodes are never
 * touched by this order, so the hardlink is safe and the swap preserves them).
 *
 * A missing live dir (first ever issuance) or a missing individual file is fine
 * — there is simply nothing to carry forward. linkat is done relative to a
 * freshly-pinned live dir fd (O_DIRECTORY|O_NOFOLLOW) and the staging fd, so a
 * swapped <dir> component cannot redirect a link outside the store. A symlinked
 * or non-regular live file is skipped (we only carry forward real cert files).
 *
 * NOT best-effort on a PRESENT file. If an existing regular other-keytype file
 * cannot be linked into staging (cross-device, ENOSPC, permission, …), seeding
 * MUST fail: the subsequent whole-<seg> RENAME_EXCHANGE would otherwise publish
 * a live dir missing that file and the cleanup of the old dir would then destroy
 * the only copy — i.e. the other keytype's live cert is lost. So this is a
 * commit precondition; the caller aborts the store on NGX_ERROR (the existing
 * live dir is left untouched). Returns NGX_OK when staging holds a faithful copy
 * of every present other-keytype file.
 */
static ngx_int_t
ngx_autocert_order_seed_staging_at(ngx_autocert_order_t *order, int cfd,
    const char *dir, int sfd, ngx_uint_t skip_kt)
{
    int           lfd, i;
    struct stat   st;
    const char   *name;
    const char   *sp, *sc, *sl, *sr;

    /* This keytype's own names — excluded from seeding (see CRITICAL above). */
    ngx_autocert_keytype_pem_names(skip_kt, &sp, &sc, &sl, &sr);

    lfd = openat(cfd, dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (lfd == -1) {
        /* No live dir yet (first issuance), or it is not a real dir — nothing
         * to carry forward. A non-dir live entry is handled by the commit. */
        return NGX_OK;
    }

    for (i = 0; (name = ngx_autocert_store_files[i]) != NULL; i++) {

        if (ngx_strcmp(name, sp) == 0 || ngx_strcmp(name, sc) == 0
            || ngx_strcmp(name, sl) == 0 || ngx_strcmp(name, sr) == 0)
        {
            continue;                   /* this keytype overwrites it; never seed */
        }

        /* Only hardlink real, regular files; skip symlinks/dirs/specials so a
         * planted non-regular entry can't be carried into staging. A missing
         * file (ENOENT) is fine — the other keytype simply has not issued it. */
        if (fstatat(lfd, name, &st, AT_SYMLINK_NOFOLLOW) == -1) {
            continue;
        }
        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        if (linkat(lfd, name, sfd, name, 0) == -1 && ngx_errno != NGX_EEXIST) {
            /* A PRESENT regular file we could not carry forward. Failing the
             * seed here keeps the live dir intact (caller aborts before any
             * swap) rather than publishing a dir that drops this file. */
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: seed staging linkat(\"%s\") failed; "
                          "aborting store to preserve the live cert", name);
            (void) close(lfd);
            return NGX_ERROR;
        }
    }

    (void) close(lfd);
    return NGX_OK;
}


/*
 * Atomically swap the staging leaf with the live leaf via
 * renameat2(RENAME_EXCHANGE), both relative to the pinned container dir fd.
 * Returns NGX_OK on success, NGX_DECLINED when the kernel/filesystem does not
 * support the flag (caller falls back), NGX_ERROR on any other failure.
 */
static ngx_int_t
ngx_autocert_order_swap_dirs_at(ngx_autocert_order_t *order, int cfd,
    const char *staging, const char *dir)
{
    ngx_int_t  rc;

    rc = ngx_autocert_renameat2(cfd, staging, cfd, dir, RENAME_EXCHANGE);

    if (rc == NGX_DECLINED) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, order->log, 0,
                       "autocert: RENAME_EXCHANGE unsupported, "
                       "falling back to sequential rename");
        return NGX_DECLINED;
    }
    if (rc == NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: renameat2(RENAME_EXCHANGE \"%s\" <-> \"%s\") "
                      "failed", staging, dir);
    }
    return rc;
}


/* Write data to <leaf> inside the pinned staging dir fd (mode), force perms,
 * fsync, close. Leaves the file in place for the caller; unlinks it on failure.
 * O_NOFOLLOW guards the leaf component; the dir fd guards the parent chain. */
static ngx_int_t
ngx_autocert_order_write_tmp_at(ngx_autocert_order_t *order, int sfd,
    const char *leaf, ngx_str_t *data, ngx_uint_t mode)
{
    int      fd;
    size_t   off;
    ssize_t  n;

    fd = openat(sfd, leaf,
                O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                (mode_t) mode);
    if (fd == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: open(\"%s\") failed", leaf);
        return NGX_ERROR;
    }

    /* O_CREAT honours umask; force the intended perms regardless. */
    if (fchmod(fd, (mode_t) mode) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: fchmod(\"%s\") failed", leaf);
        (void) close(fd);
        (void) unlinkat(sfd, leaf, 0);
        return NGX_ERROR;
    }

    for (off = 0; off < data->len; off += n) {
        n = write(fd, data->data + off, data->len - off);
        if (n == -1) {
            if (ngx_errno == EINTR) {
                n = 0;
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                          "autocert: write(\"%s\") failed", leaf);
            (void) close(fd);
            (void) unlinkat(sfd, leaf, 0);
            return NGX_ERROR;
        }
        if (n == 0) {
            /* zero progress on a non-empty remainder — fail rather than spin. */
            ngx_log_error(NGX_LOG_ERR, order->log, 0,
                          "autocert: write(\"%s\") made no progress", leaf);
            (void) close(fd);
            (void) unlinkat(sfd, leaf, 0);
            return NGX_ERROR;
        }
    }

    if (fsync(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: fsync(\"%s\") failed", leaf);
        (void) close(fd);
        (void) unlinkat(sfd, leaf, 0);
        return NGX_ERROR;
    }

    if (close(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, order->log, ngx_errno,
                      "autocert: close(\"%s\") failed", leaf);
        (void) unlinkat(sfd, leaf, 0);
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

    /* M16 dns-01: remove the published TXT via the remove-hook. Cleanup failure
     * is non-fatal — the record expires by TTL — so the result is ignored. An
     * empty hook (plumbing/stub path) just clears the flag. */
    if (order->dns_set) {
        if (order->dns_hook_remove.len != 0) {
            (void) ngx_autocert_order_dns_hook(order, &order->dns_hook_remove,
                                               0);
        }
        order->dns_set = 0;
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
    if (order->dns_delay_timer.timer_set) {
        ngx_del_timer(&order->dns_delay_timer);
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
    if (order->dns_delay_timer.timer_set) {
        ngx_del_timer(&order->dns_delay_timer);
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
