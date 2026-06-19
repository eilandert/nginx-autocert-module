/*
 * ngx_autocert_challenge — shared-memory HTTP-01 token store (M5).
 * See the header for the contract. An rbtree of token->keyauth in a slab zone,
 * keyed by crc32(token) with the full token compared on collision.
 */

#include "ngx_autocert_challenge.h"


static ngx_autocert_challenge_node_t *ngx_autocert_challenge_lookup(
    ngx_autocert_challenge_sh_t *sh, ngx_str_t *token, uint32_t hash);


/*
 * rbtree insert ordering: by node->key (crc32) then token length then the
 * token bytes — matching ngx_autocert_challenge_lookup() exactly. A custom
 * insert is required because the node is NOT an ngx_str_node_t (the token is
 * stored inline, not as an ngx_str_t member), so ngx_str_rbtree_insert_value
 * would misread it.
 */
static void
ngx_autocert_challenge_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t             **p;
    ngx_autocert_challenge_node_t  *cn, *cnt;

    for ( ;; ) {
        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else {
            cn = (ngx_autocert_challenge_node_t *) node;
            cnt = (ngx_autocert_challenge_node_t *) temp;

            if (cn->token_len != cnt->token_len) {
                p = (cn->token_len < cnt->token_len) ? &temp->left
                                                     : &temp->right;
            } else {
                p = (ngx_memcmp(cn->token, cnt->token, cn->token_len) < 0)
                    ? &temp->left : &temp->right;
            }
        }

        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_int_t
ngx_autocert_challenge_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t              *shpool;
    ngx_autocert_challenge_sh_t  *sh;

    /* Inherit the previous incarnation's tree across reload (noreuse off). */
    if (shm_zone->shm.exists) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: challenge zone inherited from old cycle");
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    sh = ngx_slab_alloc(shpool, sizeof(ngx_autocert_challenge_sh_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    shpool->data = sh;

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel,
                    ngx_autocert_challenge_insert_value);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: challenge zone initialized");

    return NGX_OK;
}


static ngx_autocert_challenge_node_t *
ngx_autocert_challenge_lookup(ngx_autocert_challenge_sh_t *sh,
    ngx_str_t *token, uint32_t hash)
{
    ngx_rbtree_node_t              *node, *sentinel;
    ngx_autocert_challenge_node_t  *cn;
    ngx_int_t                       rc;

    node = sh->rbtree.root;
    sentinel = sh->rbtree.sentinel;

    while (node != sentinel) {
        if (hash < node->key) {
            node = node->left;
            continue;
        }
        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key: compare the full token (length then bytes). */
        cn = (ngx_autocert_challenge_node_t *) node;

        if (token->len != cn->token_len) {
            node = (token->len < cn->token_len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(token->data, cn->token, token->len);
        if (rc == 0) {
            return cn;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


ngx_int_t
ngx_autocert_challenge_set(ngx_shm_zone_t *shm_zone, ngx_str_t *token,
    ngx_str_t *keyauth)
{
    ngx_slab_pool_t                *shpool;
    ngx_autocert_challenge_sh_t    *sh;
    ngx_autocert_challenge_node_t  *cn;
    uint32_t                        hash;
    u_char                         *ka;

    if (token->len == 0 || token->len > NGX_AUTOCERT_TOKEN_MAX
        || keyauth->len == 0 || keyauth->len > NGX_AUTOCERT_KEYAUTH_MAX)
    {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: set rejected bounds token len %uz keyauth len %uz",
                       token->len, keyauth->len);
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: set token \"%V\" keyauth %uz bytes",
                   token, keyauth->len);

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(token->data, token->len);

    ngx_shmtx_lock(&shpool->mutex);

    cn = ngx_autocert_challenge_lookup(sh, token, hash);

    if (cn != NULL) {
        /* replace the keyauth value in place */
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: set replacing existing token \"%V\"", token);
        ka = ngx_slab_alloc_locked(shpool, keyauth->len);
        if (ka == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }
        ngx_memcpy(ka, keyauth->data, keyauth->len);
        ngx_slab_free_locked(shpool, cn->keyauth.data);
        cn->keyauth.data = ka;
        cn->keyauth.len = keyauth->len;
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    /* new node: header + inline token bytes */
    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: set inserting new token \"%V\"", token);

    cn = ngx_slab_alloc_locked(shpool,
             offsetof(ngx_autocert_challenge_node_t, token) + token->len);
    if (cn == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    ka = ngx_slab_alloc_locked(shpool, keyauth->len);
    if (ka == NULL) {
        ngx_slab_free_locked(shpool, cn);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    cn->node.key = hash;
    cn->token_len = (u_short) token->len;
    ngx_memcpy(cn->token, token->data, token->len);
    ngx_memcpy(ka, keyauth->data, keyauth->len);
    cn->keyauth.data = ka;
    cn->keyauth.len = keyauth->len;

    ngx_rbtree_insert(&sh->rbtree, &cn->node);

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_autocert_challenge_remove(ngx_shm_zone_t *shm_zone, ngx_str_t *token)
{
    ngx_slab_pool_t                *shpool;
    ngx_autocert_challenge_sh_t    *sh;
    ngx_autocert_challenge_node_t  *cn;
    uint32_t                        hash;

    if (token->len == 0 || token->len > NGX_AUTOCERT_TOKEN_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: remove rejected bounds token len %uz",
                       token->len);
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(token->data, token->len);

    ngx_shmtx_lock(&shpool->mutex);

    cn = ngx_autocert_challenge_lookup(sh, token, hash);
    if (cn != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: remove found token \"%V\", deleting", token);
        ngx_rbtree_delete(&sh->rbtree, &cn->node);
        ngx_slab_free_locked(shpool, cn->keyauth.data);
        ngx_slab_free_locked(shpool, cn);
    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: remove token \"%V\" absent", token);
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_autocert_challenge_get(ngx_shm_zone_t *shm_zone, ngx_str_t *token,
    ngx_pool_t *pool, ngx_str_t *out)
{
    ngx_slab_pool_t                *shpool;
    ngx_autocert_challenge_sh_t    *sh;
    ngx_autocert_challenge_node_t  *cn;
    uint32_t                        hash;
    u_char                          buf[NGX_AUTOCERT_KEYAUTH_MAX];
    size_t                          len;

    if (token->len == 0 || token->len > NGX_AUTOCERT_TOKEN_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: get rejected bounds token len %uz",
                       token->len);
        return NGX_DECLINED;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(token->data, token->len);

    ngx_shmtx_lock(&shpool->mutex);

    cn = ngx_autocert_challenge_lookup(sh, token, hash);
    if (cn == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: get miss token \"%V\"", token);
        return NGX_DECLINED;
    }

    len = cn->keyauth.len;
    ngx_memcpy(buf, cn->keyauth.data, len);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: get hit token \"%V\" keyauth %uz bytes",
                   token, len);

    ngx_shmtx_unlock(&shpool->mutex);

    out->data = ngx_pnalloc(pool, len);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(out->data, buf, len);
    out->len = len;

    return NGX_OK;
}
