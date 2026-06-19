/*
 * ngx_autocert_alpn — shared-memory tls-alpn-01 challenge certificate store
 * (M10b). See the header for the contract. An rbtree of domain->{cert,key} PEM
 * in a slab zone, keyed by crc32(domain) with the full domain compared on
 * collision. Structurally a sibling of ngx_autocert_challenge with a two-part
 * value instead of one.
 */

#include "ngx_autocert_alpn.h"


static ngx_autocert_alpn_node_t *ngx_autocert_alpn_lookup(
    ngx_autocert_alpn_sh_t *sh, ngx_str_t *domain, uint32_t hash);


/*
 * rbtree insert ordering: by node->key (crc32) then domain length then the
 * domain bytes — matching ngx_autocert_alpn_lookup() exactly. A custom insert
 * is required because the node is NOT an ngx_str_node_t (the domain is stored
 * inline, not as an ngx_str_t member), so ngx_str_rbtree_insert_value would
 * misread it.
 */
static void
ngx_autocert_alpn_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t         **p;
    ngx_autocert_alpn_node_t   *an, *ant;

    for ( ;; ) {
        if (node->key != temp->key) {
            p = (node->key < temp->key) ? &temp->left : &temp->right;

        } else {
            an = (ngx_autocert_alpn_node_t *) node;
            ant = (ngx_autocert_alpn_node_t *) temp;

            if (an->domain_len != ant->domain_len) {
                p = (an->domain_len < ant->domain_len) ? &temp->left
                                                       : &temp->right;
            } else {
                p = (ngx_memcmp(an->domain, ant->domain, an->domain_len) < 0)
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
ngx_autocert_alpn_init_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t         *shpool;
    ngx_autocert_alpn_sh_t  *sh;

    /* Inherit the previous incarnation's tree across reload (noreuse off). */
    if (shm_zone->shm.exists) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn zone inherited from old cycle");
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    sh = ngx_slab_alloc(shpool, sizeof(ngx_autocert_alpn_sh_t));
    if (sh == NULL) {
        return NGX_ERROR;
    }

    shpool->data = sh;

    ngx_rbtree_init(&sh->rbtree, &sh->sentinel,
                    ngx_autocert_alpn_insert_value);

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: alpn zone initialized");

    return NGX_OK;
}


static ngx_autocert_alpn_node_t *
ngx_autocert_alpn_lookup(ngx_autocert_alpn_sh_t *sh, ngx_str_t *domain,
    uint32_t hash)
{
    ngx_rbtree_node_t         *node, *sentinel;
    ngx_autocert_alpn_node_t  *an;
    ngx_int_t                  rc;

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

        /* hash == node->key: compare the full domain (length then bytes). */
        an = (ngx_autocert_alpn_node_t *) node;

        if (domain->len != an->domain_len) {
            node = (domain->len < an->domain_len) ? node->left : node->right;
            continue;
        }

        rc = ngx_memcmp(domain->data, an->domain, domain->len);
        if (rc == 0) {
            return an;
        }
        node = (rc < 0) ? node->left : node->right;
    }

    return NULL;
}


ngx_int_t
ngx_autocert_alpn_set(ngx_shm_zone_t *shm_zone, ngx_str_t *domain,
    ngx_str_t *cert, ngx_str_t *key)
{
    ngx_slab_pool_t           *shpool;
    ngx_autocert_alpn_sh_t    *sh;
    ngx_autocert_alpn_node_t  *an;
    uint32_t                   hash;
    u_char                    *cp, *kp;

    if (domain->len == 0 || domain->len > NGX_AUTOCERT_ALPN_DOMAIN_MAX
        || cert->len == 0 || cert->len > NGX_AUTOCERT_ALPN_CERT_MAX
        || key->len == 0 || key->len > NGX_AUTOCERT_ALPN_KEY_MAX)
    {
        ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn set rejected bounds domain len %uz "
                       "cert len %uz key len %uz",
                       domain->len, cert->len, key->len);
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(domain->data, domain->len);

    ngx_log_debug3(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: alpn set \"%V\" cert %uz bytes key %uz bytes",
                   domain, cert->len, key->len);

    ngx_shmtx_lock(&shpool->mutex);

    an = ngx_autocert_alpn_lookup(sh, domain, hash);

    if (an != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn set \"%V\" replacing existing node",
                       domain);

        /* Replace the value in place. Allocate both new blobs before freeing
         * the old ones so a mid-way OOM leaves the existing pair intact. */
        cp = ngx_slab_alloc_locked(shpool, cert->len);
        if (cp == NULL) {
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }
        kp = ngx_slab_alloc_locked(shpool, key->len);
        if (kp == NULL) {
            ngx_slab_free_locked(shpool, cp);
            ngx_shmtx_unlock(&shpool->mutex);
            return NGX_ERROR;
        }
        ngx_memcpy(cp, cert->data, cert->len);
        ngx_memcpy(kp, key->data, key->len);
        ngx_slab_free_locked(shpool, an->cert.data);
        ngx_slab_free_locked(shpool, an->key.data);
        an->cert.data = cp;
        an->cert.len = cert->len;
        an->key.data = kp;
        an->key.len = key->len;
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_OK;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: alpn set \"%V\" inserting new node", domain);

    /* New node: header + inline domain bytes, plus the two value blobs. */
    an = ngx_slab_alloc_locked(shpool,
             offsetof(ngx_autocert_alpn_node_t, domain) + domain->len);
    if (an == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    cp = ngx_slab_alloc_locked(shpool, cert->len);
    if (cp == NULL) {
        ngx_slab_free_locked(shpool, an);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    kp = ngx_slab_alloc_locked(shpool, key->len);
    if (kp == NULL) {
        ngx_slab_free_locked(shpool, cp);
        ngx_slab_free_locked(shpool, an);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }

    an->node.key = hash;
    an->domain_len = (u_short) domain->len;
    ngx_memcpy(an->domain, domain->data, domain->len);
    ngx_memcpy(cp, cert->data, cert->len);
    ngx_memcpy(kp, key->data, key->len);
    an->cert.data = cp;
    an->cert.len = cert->len;
    an->key.data = kp;
    an->key.len = key->len;

    ngx_rbtree_insert(&sh->rbtree, &an->node);

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_autocert_alpn_remove(ngx_shm_zone_t *shm_zone, ngx_str_t *domain)
{
    ngx_slab_pool_t           *shpool;
    ngx_autocert_alpn_sh_t    *sh;
    ngx_autocert_alpn_node_t  *an;
    uint32_t                   hash;

    if (domain->len == 0 || domain->len > NGX_AUTOCERT_ALPN_DOMAIN_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn remove rejected bounds domain len %uz",
                       domain->len);
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(domain->data, domain->len);

    ngx_shmtx_lock(&shpool->mutex);

    an = ngx_autocert_alpn_lookup(sh, domain, hash);
    if (an != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn remove \"%V\" found, deleting", domain);
        ngx_rbtree_delete(&sh->rbtree, &an->node);
        ngx_slab_free_locked(shpool, an->cert.data);
        ngx_slab_free_locked(shpool, an->key.data);
        ngx_slab_free_locked(shpool, an);

    } else {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn remove \"%V\" absent", domain);
    }

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}


ngx_int_t
ngx_autocert_alpn_get(ngx_shm_zone_t *shm_zone, ngx_str_t *domain,
    ngx_pool_t *pool, ngx_str_t *cert, ngx_str_t *key)
{
    ngx_slab_pool_t           *shpool;
    ngx_autocert_alpn_sh_t    *sh;
    ngx_autocert_alpn_node_t  *an;
    uint32_t                   hash;
    u_char                    *cp, *kp;

    if (domain->len == 0 || domain->len > NGX_AUTOCERT_ALPN_DOMAIN_MAX) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn get rejected bounds domain len %uz",
                       domain->len);
        return NGX_DECLINED;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    sh = shpool->data;
    hash = ngx_crc32_long(domain->data, domain->len);

    ngx_shmtx_lock(&shpool->mutex);

    an = ngx_autocert_alpn_lookup(sh, domain, hash);
    if (an == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                       "autocert: alpn get \"%V\" miss", domain);
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_DECLINED;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, shm_zone->shm.log, 0,
                   "autocert: alpn get \"%V\" hit, cert %uz bytes",
                   domain, an->cert.len);

    /* Copy both values out under the lock so they stay valid after we unlock.
     * A single allocation holds both, cert first; key points into its tail. */
    cp = ngx_pnalloc(pool, an->cert.len + an->key.len);
    if (cp == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        return NGX_ERROR;
    }
    kp = cp + an->cert.len;

    ngx_memcpy(cp, an->cert.data, an->cert.len);
    ngx_memcpy(kp, an->key.data, an->key.len);

    cert->data = cp;
    cert->len = an->cert.len;
    key->data = kp;
    key->len = an->key.len;

    ngx_shmtx_unlock(&shpool->mutex);
    return NGX_OK;
}
