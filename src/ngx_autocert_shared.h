/*
 * ngx_autocert_shared — the narrow interface the CORE helper process uses to
 * read the HTTP module's configuration without depending on the HTTP module's
 * private conf struct. The helper is an NGX_CORE_MODULE; it cannot use
 * ngx_http_conf_get_module_main_conf, and the autocert main-conf struct is
 * file-private to ngx_http_autocert_module.c. So the HTTP module exports one
 * accessor that copies the few fields the helper needs into this flat struct.
 */

#ifndef _NGX_AUTOCERT_SHARED_H_INCLUDED_
#define _NGX_AUTOCERT_SHARED_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <fcntl.h>
#include <errno.h>


typedef struct {
    ngx_uint_t       configured;     /* 0 => autocert not present in http{} */
    ngx_str_t        email;          /* account contact email, "" if none */
    ngx_resolver_t  *resolver;       /* may be NULL if autocert_resolver unset */
    time_t           resolver_timeout;
    /*
     * M5: the CA-identifying knobs (directory URL, trust bundle, EAB) are no
     * longer flat — they live per-CA in each ca_list entry's ca_conf. The driver
     * iterates ca_list and reads entry->ca_conf directly (see driver.c). The flat
     * `ca`/`ca_certificate`/`eab_*` fields the M4 bridge populated from ca_list[0]
     * are gone.
     */
    ngx_str_t        dns_hook_add;     /* M16 dns-01 publish-TXT exec, "" */
    ngx_str_t        dns_hook_remove;  /* M16 dns-01 remove-TXT exec, "" */
    time_t           dns_propagation_delay;  /* M16 seconds after publish */
    time_t           dns_hook_timeout;  /* M16 seconds to wait for a hook exec */
    ngx_uint_t       key_type;       /* ngx_http_autocert_key_type_e; == cert_key_types[0],
                                        kept for not-yet-array-aware consumers */
    ngx_array_t     *cert_key_types; /* dual-cert (Phase B): ngx_uint_t list of leaf
                                        key types to issue per name (1..4). The ACME
                                        account/challenge keys stay EC regardless. */
    ngx_uint_t       store;          /* ngx_http_autocert_store_e (disk layout) */
    ngx_str_t        path;           /* cert store dir (holds the account key) */
    time_t           renew_before;   /* M8: seconds before notAfter to renew */
    ngx_uint_t       challenge;      /* M10c: ngx_http_autocert_challenge_e */

    /* M5: the challenge token store the helper writes (NULL if not set up). */
    ngx_shm_zone_t  *challenge_zone;
    /* M6a: the collected enabled server names (ngx_str_t array, NULL/empty if
     * none). The order flow issues for the first name for now; multi-name
     * iteration is later (M6+). Points into the HTTP main-conf pool, which
     * outlives the helper run. */
    ngx_array_t     *names;
    /* M2: names grouped by CA (ngx_autocert_ca_entry_t array). One entry until
     * M4 adds per-vhost CAs; the driver (M5) iterates this. NULL/empty = none. */
    ngx_array_t     *ca_list;
    /* M5 test seed (token.len == 0 when unset). */
    ngx_str_t        test_token;
    ngx_str_t        test_keyauth;

    /* M10b: the tls-alpn-01 challenge cert store the helper writes (NULL if not
     * set up). */
    ngx_shm_zone_t  *alpn_zone;
    /* M10b test seed (domain.len == 0 when unset). */
    ngx_str_t        test_alpn_domain;
    ngx_str_t        test_alpn_keyauth;
} ngx_autocert_conf_t;


/*
 * Fill *out from the running cycle's HTTP autocert main conf. Returns NGX_OK
 * with out->configured set appropriately (0 if the http{} block has no
 * autocert main conf, e.g. no http{} at all), NGX_ERROR only on a NULL out.
 * Safe to call from the helper (CORE) process against its own cycle.
 */
ngx_int_t ngx_autocert_get_conf(ngx_cycle_t *cycle, ngx_autocert_conf_t *out);


/*
 * renameat2(2) wrapper, shared by the store commit (order.c) and the account-key
 * migration (driver.c) — both fd-pinned, security-sensitive renames that must
 * not drift. Called via syscall() so the build needs no glibc renameat2 wrapper.
 * Returns NGX_OK on success; NGX_DECLINED when the syscall/flag is unsupported
 * (caller falls back or defers); NGX_ERROR otherwise with ngx_errno set (incl.
 * EEXIST for RENAME_NOREPLACE against an existing destination — caller inspects).
 */
#if defined(__linux__)
#include <sys/syscall.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1 << 0)
#endif
#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif
#endif


/*
 * Open a directory without trusting any component of `path`. O_NOFOLLOW on a
 * single open(path) protects only the leaf; this walk pins every ancestor with
 * openat() before descending into the next component. If `create` is set,
 * missing components are made relative to the already-pinned parent. `path`
 * must be NUL-terminated. Returns an owned directory fd, or -1 with errno set.
 */
static ngx_inline int
ngx_autocert_open_dir_path(const char *path, ngx_uint_t create, mode_t mode)
{
    char         name[NGX_MAX_PATH];
    const char  *p, *q;
    size_t       len;
    int          dfd, nfd, err;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (path[0] == '/') {
        dfd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        p = path + 1;
    } else {
        dfd = open(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        p = path;
    }
    if (dfd == -1) {
        return -1;
    }

    while (*p) {
        q = p;
        while (*q && *q != '/') {
            q++;
        }
        len = q - p;

        if (len == 0 || (len == 1 && p[0] == '.')) {
            p = (*q == '/') ? q + 1 : q;
            continue;
        }
        if ((len == 2 && p[0] == '.' && p[1] == '.')
            || len >= sizeof(name))
        {
            err = (len >= sizeof(name)) ? ENAMETOOLONG : EINVAL;
            (void) close(dfd);
            errno = err;
            return -1;
        }

        ngx_memcpy(name, p, len);
        name[len] = '\0';
        nfd = openat(dfd, name,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nfd == -1 && create && errno == ENOENT) {
            if (mkdirat(dfd, name, mode) == -1 && errno != EEXIST) {
                err = errno;
                (void) close(dfd);
                errno = err;
                return -1;
            }
            nfd = openat(dfd, name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (nfd == -1) {
            err = errno;
            (void) close(dfd);
            errno = err;
            return -1;
        }

        (void) close(dfd);
        dfd = nfd;
        p = (*q == '/') ? q + 1 : q;
    }

    return dfd;
}


/*
 * Open a regular leaf relative to a parent directory whose every component was
 * pinned by ngx_autocert_open_dir_path(). The final leaf is also O_NOFOLLOW.
 */
static ngx_inline int
ngx_autocert_open_file_path(const char *path, int flags)
{
    char         parent[NGX_MAX_PATH];
    const char  *p, *slash, *leaf;
    size_t       len;
    int          dfd, fd, err;

    if (path == NULL || path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    slash = NULL;
    for (p = path; *p; p++) {
        if (*p == '/') {
            slash = p;
        }
    }

    if (slash == NULL) {
        dfd = ngx_autocert_open_dir_path(".", 0, 0);
        leaf = path;
    } else if (slash == path) {
        dfd = ngx_autocert_open_dir_path("/", 0, 0);
        leaf = slash + 1;
    } else {
        len = slash - path;
        if (len >= sizeof(parent)) {
            errno = ENAMETOOLONG;
            return -1;
        }
        ngx_memcpy(parent, path, len);
        parent[len] = '\0';
        dfd = ngx_autocert_open_dir_path(parent, 0, 0);
        leaf = slash + 1;
    }

    if (leaf[0] == '\0' || (leaf[0] == '.' && leaf[1] == '\0')
        || (leaf[0] == '.' && leaf[1] == '.' && leaf[2] == '\0'))
    {
        if (dfd != -1) {
            (void) close(dfd);
        }
        errno = EINVAL;
        return -1;
    }
    if (dfd == -1) {
        return -1;
    }

    fd = openat(dfd, leaf, flags | O_NOFOLLOW | O_CLOEXEC);
    err = errno;
    (void) close(dfd);
    errno = err;

    return fd;
}
static ngx_inline ngx_int_t
ngx_autocert_renameat2(int oldfd, const char *oldp, int newfd,
    const char *newp, unsigned int flags)
{
#if defined(__linux__) && defined(SYS_renameat2)
    if (syscall(SYS_renameat2, oldfd, oldp, newfd, newp, flags) == 0) {
        return NGX_OK;
    }
    if (ngx_errno == NGX_ENOSYS || ngx_errno == EINVAL
        || ngx_errno == ENOTTY || ngx_errno == EOPNOTSUPP)
    {
        return NGX_DECLINED;
    }
    return NGX_ERROR;
#else
    (void) oldfd; (void) oldp; (void) newfd; (void) newp; (void) flags;
    return NGX_DECLINED;
#endif
}


#endif /* _NGX_AUTOCERT_SHARED_H_INCLUDED_ */
