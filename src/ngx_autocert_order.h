/*
 * ngx_autocert_order — ACME order + authorization flow (M6a).
 *
 * Drives RFC 8555 issuance up to (but not including) finalization, on the
 * helper process event loop, reusing a LIVE registered account
 * (ngx_autocert_account_t) for every kid-signed POST:
 *
 *   1. POST newOrder {identifiers:[{type:dns,value:<name>}]}
 *        -> order URL (Location), authorizations[], finalize URL
 *   2. for the single authorization: POST-as-GET it
 *        -> find challenges[] with type=="http-01" -> token + challenge url
 *   3. keyauth = token "." base64url(SHA-256(account JWK))  [M3 thumbprint]
 *      challenge store SET token->keyauth  [M5], so the :80 worker can serve it
 *   4. POST the challenge url {} to tell the CA we are ready
 *   5. poll the authorization (POST-as-GET) until status=="valid"
 *      (or "invalid"/"deactivated"/"revoked"/"expired" -> fail)
 *   6. challenge store REMOVE token
 *
 * M6a handles exactly ONE identifier (the first collected server name). The
 * order URL + finalize URL + the validated CSR are what M6b consumes to finish
 * issuance, so they are exposed on the order struct after a successful run.
 *
 * Single in-flight order per helper. The caller allocates the order struct,
 * fills the inputs, and is notified once via the handler with NGX_OK (authz
 * valid; order_url/finalize_url set) or NGX_ERROR.
 */

#ifndef _NGX_AUTOCERT_ORDER_H_INCLUDED_
#define _NGX_AUTOCERT_ORDER_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include "ngx_autocert_account.h"


typedef struct ngx_autocert_order_s  ngx_autocert_order_t;

typedef void (*ngx_autocert_order_handler_pt)(ngx_autocert_order_t *order,
    ngx_int_t rc);


struct ngx_autocert_order_s {
    /* inputs (caller fills before _start) */
    ngx_autocert_account_t          *account;       /* live, registered */
    ngx_log_t                       *log;
    ngx_str_t                        directory_url;  /* ACME directory */
    ngx_str_t                        domain;         /* identifier (one) */
    ngx_shm_zone_t                  *challenge_zone; /* M5 token store */

    ngx_autocert_order_handler_pt    handler;
    void                            *data;

    /* outputs (valid on handler NGX_OK) — consumed by M6b */
    ngx_str_t                        order_url;      /* order resource URL */
    ngx_str_t                        finalize_url;   /* finalize endpoint */

    /* internals */
    ngx_pool_t                      *pool;           /* whole-order pool */
    ngx_str_t                        new_order_url;
    ngx_str_t                        authz_url;       /* the one authorization */
    ngx_str_t                        challenge_url;    /* http-01 challenge */
    ngx_str_t                        token;            /* http-01 token */
    ngx_str_t                        keyauth;          /* token.thumbprint */
    ngx_uint_t                       poll_tries;
    ngx_uint_t                       challenge_set;    /* token in store? */
    ngx_uint_t                       done;
    ngx_event_t                      poll_timer;
};


/*
 * Allocate-and-go is the caller's job: fill account/log/directory_url/domain/
 * challenge_zone/handler, then call _start. Returns NGX_OK once started
 * (handler fires later) or NGX_ERROR if it could not start (handler NOT
 * called). On the terminal handler the caller releases resources with
 * ngx_autocert_order_free().
 */
ngx_int_t ngx_autocert_order_start(ngx_autocert_order_t *order);

void ngx_autocert_order_free(ngx_autocert_order_t *order);


#endif /* _NGX_AUTOCERT_ORDER_H_INCLUDED_ */
