/*
 * ngx_autocert_account — ACME account bootstrap on the helper process (M4d-2).
 *
 * Drives the first three steps of the ACME protocol (RFC 8555) using the M4b
 * HTTPS client, the M4c JSON reader and the M3 JOSE/ECDSA crypto, all of which
 * are compiled into the CORE helper module:
 *
 *   1. GET  <directory>            — discover newNonce / newAccount URLs (M4c)
 *   2. GET  <newNonce>             — take the Replay-Nonce response header (M4d-1)
 *   3. POST <newAccount> (JWS)     — register; the account URL ("kid") comes back
 *                                    in the Location response header
 *
 * The account key (ECDSA, curve from autocert_key_type) is loaded from
 * <autocert_path>/account.key if present, else generated and persisted there
 * with 0600 perms. After a successful register, the account holds the key and
 * the kid that every later ACME POST (newOrder, finalize, …) signs with.
 *
 * Single in-flight account bootstrap per helper; the steps chain through the
 * client's completion callbacks on the helper event loop. The caller is
 * notified once via the handler with NGX_OK (acct->kid valid) or NGX_ERROR.
 */

#ifndef _NGX_AUTOCERT_ACCOUNT_H_INCLUDED_
#define _NGX_AUTOCERT_ACCOUNT_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>

#include "ngx_autocert_acme.h"


typedef struct ngx_autocert_account_s  ngx_autocert_account_t;

typedef void (*ngx_autocert_account_handler_pt)(ngx_autocert_account_t *acct,
    ngx_int_t rc);


struct ngx_autocert_account_s {
    /* inputs (caller fills before _register) */
    ngx_autocert_acme_client_t      *client;
    ngx_cycle_t                     *cycle;
    ngx_log_t                       *log;
    ngx_str_t                        directory_url;  /* ACME directory */
    ngx_str_t                        key_path;       /* <path>/account.key */
    ngx_uint_t                       key_type;       /* crypto curve enum */
    ngx_str_t                        email;          /* account contact, "" */
    ngx_str_t                        eab_kid;        /* EAB key id, "" if none */
    ngx_str_t                        eab_hmac_key;   /* base64url EAB key, "" */

    ngx_autocert_account_handler_pt  handler;
    void                            *data;

    /* outputs (valid on handler NGX_OK) */
    EVP_PKEY                        *key;            /* account key (owned) */
    ngx_str_t                        kid;            /* account URL (pool) */

    /* internals */
    ngx_pool_t                      *pool;           /* whole-bootstrap pool */
    ngx_str_t                        new_nonce_url;
    ngx_str_t                        new_account_url;
    ngx_str_t                        nonce;          /* current Replay-Nonce */
    ngx_pool_t                      *nonce_pool;      /* holds nonce; reset on
                                                       * each refresh (M6a) so
                                                       * nonces don't accumulate
                                                       * in the session pool */
    ngx_uint_t                       done;

    /* in-flight kid-signed POST state (M6a). One signed POST per account at a
     * time; the order state machine chains them. */
    ngx_pool_t                      *post_pool;      /* per-POST pool */
    ngx_str_t                        post_url;       /* target (in post_pool) */
    ngx_str_t                        post_payload;   /* raw body (in post_pool) */
    ngx_autocert_acme_handler_pt     post_handler;   /* caller completion */
    void                            *post_data;      /* caller context */
    ngx_uint_t                       post_retried;   /* badNonce retry guard */
    ngx_uint_t                       register_retried; /* newAccount badNonce guard */

    /* Last-resort failure request, reserved up front at submit so the terminal
     * failure path can ALWAYS hand the caller a non-NULL req even under OOM.
     * Without it an allocation failure on the failure path delivered a NULL req,
     * which the order handlers ignore -> the order never finishes and the
     * single-in-flight scheduler stalls forever. Consumed by post_fail (then
     * owned by the caller), or freed on the success terminal. */
    ngx_pool_t                      *post_fail_pool;
    ngx_autocert_acme_request_t     *post_fail_req;
};


/*
 * Allocate + start an account bootstrap. acct fields client/cycle/log/
 * directory_url/key_path/key_type/handler must be set; acct itself should be
 * allocated by the caller (e.g. from a pool the helper owns) and must outlive
 * the async flow until the handler fires. Returns NGX_OK once started (handler
 * fires later) or NGX_ERROR if it could not start (handler NOT called).
 *
 * On the terminal handler the account key (acct->key) is owned by the caller
 * and must be released with ngx_autocert_account_free().
 */
ngx_int_t ngx_autocert_account_register(ngx_autocert_account_t *acct);

void ngx_autocert_account_free(ngx_autocert_account_t *acct);


/*
 * Kid-signed ACME POST (M6a) — the account owns the kid, key and current nonce,
 * so every authenticated request (newOrder, authz/order POST-as-GET, challenge
 * respond, finalize) goes through here. Builds the protected header
 *   {"alg":…,"kid":"<acct kid>","nonce":"<acct nonce>","url":"<url>"}
 * signs a flattened JWS over `payload` (pass an EMPTY payload for POST-as-GET),
 * and POSTs application/jose+json. On a 2xx the account nonce is refreshed from
 * the response Replay-Nonce header. On an ACME "badNonce" error the request is
 * retried ONCE after re-fetching newNonce.
 *
 * The completion handler is invoked exactly once with the finished request (so
 * the caller can read req->status / req->body_out / response headers) and rc
 * (NGX_OK if a response was received — inspect status — or NGX_ERROR on a
 * transport failure or if the retry was also exhausted). The request pool is
 * the caller's to destroy from inside the handler, as with the raw client; on
 * NGX_ERROR a reserved synthetic req is supplied with status 0 when no HTTP
 * response survived.
 *
 * acct must be a registered account (acct->kid set). Returns NGX_OK once the
 * request is started (handler fires later) or NGX_ERROR if it could not start
 * (handler NOT called).
 */
ngx_int_t ngx_autocert_account_post(ngx_autocert_account_t *acct,
    ngx_str_t *url, ngx_str_t *payload, ngx_autocert_acme_handler_pt handler,
    void *data);


#endif /* _NGX_AUTOCERT_ACCOUNT_H_INCLUDED_ */
