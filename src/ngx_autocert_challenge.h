/*
 * ngx_autocert_challenge — shared-memory HTTP-01 challenge token store (M5).
 *
 * The ACME helper process discovers a per-authorization token and computes its
 * key authorization (token "." base64url(SHA-256(account JWK))). The HTTP-01
 * validation request, however, arrives at a worker process on :80 as
 *   GET /.well-known/acme-challenge/<token>
 * so the token->keyauth mapping must cross the process boundary. This is that
 * map: an rbtree in a shared-memory slab zone, written by the helper and read
 * by the workers under the zone's slab mutex.
 *
 * The store functions are compiled into BOTH the CORE helper module (writer)
 * and the HTTP module (reader): the two .so do not cross-resolve symbols, and
 * both operate on the same shared slab addressed through the zone, so a
 * duplicated copy in each is correct (cf. the crypto TU). The shared header
 * fixes the node layout both copies must agree on.
 *
 * Tokens are short ASCII (RFC 8555 base64url, ~43 chars); keyauths are a bit
 * longer. Both are bounded below so a malformed value can't bloat the slab.
 */

#ifndef _NGX_AUTOCERT_CHALLENGE_H_INCLUDED_
#define _NGX_AUTOCERT_CHALLENGE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* Upper bounds (defensive); real ACME values are well under these. */
#define NGX_AUTOCERT_TOKEN_MAX     128
#define NGX_AUTOCERT_KEYAUTH_MAX   512

/* token_len is stored as u_short and the inline token copy uses the full
 * token->len, so the cap MUST fit in a u_short or the two would desync on an
 * over-long token. Compile-time guard (negative array size if violated). */
typedef char ngx_autocert_token_max_fits_ushort[
    (NGX_AUTOCERT_TOKEN_MAX <= 65535) ? 1 : -1];


/* One challenge entry in the slab rbtree: token is the key, keyauth the value.
 * The token bytes follow the node inline (str rbtree node convention); keyauth
 * is a separate slab allocation pointed to by `keyauth`. */
typedef struct {
    ngx_rbtree_node_t   node;        /* node.key = ngx_crc32 of the token */
    ngx_str_t           keyauth;     /* slab-allocated value */
    u_short             token_len;
    u_char              token[1];    /* token_len bytes, inline */
} ngx_autocert_challenge_node_t;


/* Zone-wide shared header (lives at shpool->data). */
typedef struct {
    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;
} ngx_autocert_challenge_sh_t;


/*
 * Zone init callback for ngx_shared_memory_add(): sets up the rbtree in the
 * slab. Pass as shm_zone->init; data is ignored.
 */
ngx_int_t ngx_autocert_challenge_init_zone(ngx_shm_zone_t *shm_zone,
    void *data);


/*
 * Insert or replace token->keyauth in the zone (helper side). Copies both into
 * slab memory under the slab mutex. Returns NGX_OK, NGX_ERROR on a bad
 * argument / slab OOM. Re-inserting an existing token replaces its keyauth.
 */
ngx_int_t ngx_autocert_challenge_set(ngx_shm_zone_t *shm_zone,
    ngx_str_t *token, ngx_str_t *keyauth);


/*
 * Remove a token (helper side, after the authorization is validated). Returns
 * NGX_OK whether or not it was present.
 */
ngx_int_t ngx_autocert_challenge_remove(ngx_shm_zone_t *shm_zone,
    ngx_str_t *token);


/*
 * Look up a token and copy its keyauth into *out, allocated from `pool`
 * (worker side, in the request). Returns NGX_OK if found (out set), NGX_DECLINED
 * if absent, NGX_ERROR on a bad argument / OOM. Copying out under the lock keeps
 * the value stable even if the helper removes it right after.
 */
ngx_int_t ngx_autocert_challenge_get(ngx_shm_zone_t *shm_zone,
    ngx_str_t *token, ngx_pool_t *pool, ngx_str_t *out);


#endif /* _NGX_AUTOCERT_CHALLENGE_H_INCLUDED_ */
