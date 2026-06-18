/*
 * ngx_autocert_order — ACME order + authorization flow (M6a). See the header
 * for the contract. A chained state machine over the live account's kid-signed
 * POST primitive (ngx_autocert_account_post) plus one unauthenticated GET for
 * the directory's newOrder URL. Any failure funnels to _finish(NGX_ERROR).
 */

#include "ngx_autocert_order.h"
#include "ngx_autocert_acme.h"
#include "ngx_autocert_json.h"
#include "ngx_autocert_challenge.h"
#include "ngx_http_autocert_crypto.h"


/* Authorization poll: up to ~30 tries, 1s apart (Pebble validates fast; real
 * CAs take a few seconds). */
#define NGX_AUTOCERT_ORDER_POLL_MAX     30
#define NGX_AUTOCERT_ORDER_POLL_DELAY   1000    /* ms */


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
static void ngx_autocert_order_finish(ngx_autocert_order_t *order,
    ngx_int_t rc);
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


ngx_int_t
ngx_autocert_order_start(ngx_autocert_order_t *order)
{
    order->done = 0;
    order->challenge_set = 0;
    order->poll_tries = 0;
    ngx_str_null(&order->order_url);
    ngx_str_null(&order->finalize_url);
    ngx_str_null(&order->new_order_url);
    ngx_str_null(&order->authz_url);
    ngx_str_null(&order->challenge_url);
    ngx_str_null(&order->token);
    ngx_str_null(&order->keyauth);

    if (order->account == NULL || order->account->kid.len == 0
        || order->domain.len == 0)
    {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: order start without account/domain");
        return NGX_ERROR;
    }

    order->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, order->log);
    if (order->pool == NULL) {
        return NGX_ERROR;
    }

    /* Step 1: GET the directory to discover the newOrder URL. */
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

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        if (root != NULL
            && ngx_autocert_json_object_str(root, "newOrder", &no) == NGX_OK
            && ngx_autocert_order_dup(order, &order->new_order_url, &no)
               == NGX_OK)
        {
            ok = NGX_OK;
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
                    && (az = a0->u.string, 1)
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

    return ngx_autocert_account_post(order->account, &order->authz_url, &empty,
                                     ngx_autocert_order_authz_done, order);
}


static void
ngx_autocert_order_authz_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_order_t       *order;
    ngx_autocert_json_value_t  *root, *challenges, *ch;
    ngx_str_t                   thumb, token, type, url, keyauth;
    ngx_uint_t                  i, n;
    u_char                     *p;
    ngx_int_t                   ok = NGX_ERROR;

    if (req == NULL) {
        return;
    }

    order = req->data;

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        challenges = (root != NULL)
                     ? ngx_autocert_json_object_get(root, "challenges") : NULL;

        if (challenges != NULL) {
            n = ngx_autocert_json_array_count(challenges);

            for (i = 0; i < n; i++) {
                ch = ngx_autocert_json_array_item(challenges, i);
                if (ch == NULL) {
                    continue;
                }
                if (ngx_autocert_json_object_str(ch, "type", &type) != NGX_OK
                    || type.len != sizeof("http-01") - 1
                    || ngx_strncmp(type.data, "http-01",
                                   sizeof("http-01") - 1) != 0)
                {
                    continue;
                }
                if (ngx_autocert_json_object_str(ch, "token", &token) == NGX_OK
                    && ngx_autocert_json_object_str(ch, "url", &url) == NGX_OK
                    && ngx_autocert_order_dup(order, &order->token, &token)
                       == NGX_OK
                    && ngx_autocert_order_dup(order, &order->challenge_url,
                                              &url) == NGX_OK)
                {
                    ok = NGX_OK;
                    break;          /* complete usable http-01 challenge */
                }
                /* malformed http-01 entry — keep scanning for a usable one */
            }
        }
    }

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: no http-01 challenge in authorization "
                      "(status %ui)", req->status);
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

    ngx_destroy_pool(req->pool);

    /* Publish token->keyauth so the :80 worker handler can answer the VA. */
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

    if (ngx_autocert_order_respond(order) != NGX_OK) {
        ngx_autocert_order_finish(order, NGX_ERROR);
    }
}


/* Step 4: POST the challenge URL with {} to tell the CA we are ready. */
static ngx_int_t
ngx_autocert_order_respond(ngx_autocert_order_t *order)
{
    ngx_str_t  payload = ngx_string("{}");

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
    valid = 0;
    pending = 0;

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
        ngx_autocert_order_finish(order, NGX_OK);
        return;
    }

    if (!pending) {
        ngx_log_error(NGX_LOG_ERR, order->log, 0,
                      "autocert: authorization did not become valid");
        ngx_autocert_order_finish(order, NGX_ERROR);
        return;
    }

    /* still pending/processing -> poll again after the delay */
    ngx_add_timer(&order->poll_timer, NGX_AUTOCERT_ORDER_POLL_DELAY);
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

    /* Step 6: drop the token from the store now the authz is settled. The cert
     * key authorization is no longer needed once validation completed (or
     * failed); keeping it serves no purpose and leaks slab. */
    if (order->challenge_set && order->challenge_zone != NULL
        && order->token.len != 0)
    {
        (void) ngx_autocert_challenge_remove(order->challenge_zone,
                                             &order->token);
        order->challenge_set = 0;
    }

    if (order->handler) {
        order->handler(order, rc);
    }
}


void
ngx_autocert_order_free(ngx_autocert_order_t *order)
{
    if (order->challenge_set && order->challenge_zone != NULL
        && order->token.len != 0)
    {
        (void) ngx_autocert_challenge_remove(order->challenge_zone,
                                             &order->token);
        order->challenge_set = 0;
    }
    if (order->poll_timer.timer_set) {
        ngx_del_timer(&order->poll_timer);
    }
    if (order->pool) {
        ngx_destroy_pool(order->pool);
        order->pool = NULL;
    }
}
