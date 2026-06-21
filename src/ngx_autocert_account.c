/*
 * ngx_autocert_account — ACME account bootstrap (M4d-2). See the header for the
 * contract. Implemented as a small chained state machine over the M4b HTTPS
 * client: directory -> newNonce -> POST newAccount. Each step's completion
 * handler launches the next; any failure funnels to _fail() -> the caller's
 * handler(NGX_ERROR).
 */

#include "ngx_autocert_account.h"
#include "ngx_autocert_json.h"
#include "ngx_http_autocert_crypto.h"

#include <openssl/pem.h>

#include <fcntl.h>
#include <unistd.h>


static ngx_int_t ngx_autocert_account_load_key(ngx_autocert_account_t *acct);
static ngx_int_t ngx_autocert_account_save_key(ngx_autocert_account_t *acct,
    int dfd, const char *leaf);
static ngx_int_t ngx_autocert_account_start(ngx_autocert_account_t *acct,
    ngx_str_t *method, ngx_str_t *url, ngx_str_t *body, ngx_str_t *ctype,
    ngx_autocert_acme_handler_pt handler);
static void ngx_autocert_account_directory_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static void ngx_autocert_account_nonce_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_int_t ngx_autocert_account_post_account(
    ngx_autocert_account_t *acct);
static void ngx_autocert_account_register_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static void ngx_autocert_account_register_renonce_done(
    ngx_autocert_acme_request_t *req, ngx_int_t rc);
static ngx_uint_t ngx_autocert_account_is_bad_nonce(
    ngx_autocert_acme_request_t *req);
static ngx_int_t ngx_autocert_account_set_nonce(ngx_autocert_account_t *acct,
    ngx_str_t *nonce);
static ngx_uint_t ngx_autocert_account_json_safe(ngx_str_t *s);
static ngx_int_t ngx_autocert_account_build_eab(ngx_autocert_account_t *acct,
    ngx_str_t *jwk, ngx_str_t *out);
static void ngx_autocert_account_finish(ngx_autocert_account_t *acct,
    ngx_int_t rc);


/*
 * TOCTOU hardening: open the directory that contains key_path with
 * O_DIRECTORY|O_NOFOLLOW and return its fd plus a pointer to the leaf component
 * (the basename, no '/'). The caller does openat(dirfd, leaf, ...) so neither
 * the parent chain nor the final component can be redirected through a planted
 * symlink between operations — the kernel resolves the leaf against the pinned
 * directory inode. Returns -1 on failure (errno set). On success *leaf points
 * into key_path.data (NUL-terminated original; leaf is a suffix that is itself
 * NUL-terminated because key_path is).
 *
 * To close the full parent chain (not just the final parent component), the
 * directory is opened by walking it ONE component at a time from the root:
 * each intermediate is opened O_DIRECTORY|O_NOFOLLOW relative to the previously
 * pinned fd, so a symlink planted at ANY ancestor (e.g. swapping "accounts")
 * cannot redirect the descent. A single open() of the whole parent path would
 * only protect the last component.
 */
static int
ngx_autocert_account_open_keydir(ngx_autocert_account_t *acct,
    const char **leaf)
{
    u_char  *path, *slash, *comp;
    int      dfd, nfd;

    path = acct->key_path.data;         /* NUL-terminated */

    /* Start fd: "/" for an absolute path, "." otherwise. Both NOFOLLOW. */
    if (path[0] == '/') {
        dfd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        comp = path + 1;
    } else {
        dfd = open(".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        comp = path;
    }
    if (dfd == -1) {
        ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                      "autocert: open store root failed");
        return -1;
    }

    /* Walk each "/"-separated directory component, pinning as we go. The final
     * component (after the last '/') is the leaf the caller opens itself. */
    for ( ;; ) {
        slash = (u_char *) strchr((const char *) comp, '/');
        if (slash == NULL) {
            /* comp is the leaf (the key filename). dfd is its pinned parent. */
            *leaf = (const char *) comp;
            return dfd;
        }

        if (slash == comp) {            /* empty component ("//") — skip */
            comp = slash + 1;
            continue;
        }

        *slash = '\0';                  /* temporarily isolate this component */
        nfd = openat(dfd, (char *) comp,
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        {
            ngx_err_t  err = ngx_errno;
            *slash = '/';               /* restore key_path before any return */
            (void) close(dfd);
            if (nfd == -1) {
                ngx_log_error(NGX_LOG_ERR, acct->log, err,
                              "autocert: open key dir component failed");
                return -1;
            }
        }
        dfd = nfd;
        comp = slash + 1;
    }
}


/* Copy an ngx_str_t value into the bootstrap pool (the source aliases a
 * per-request pool that is freed when that request completes). */
static ngx_int_t
ngx_autocert_account_dup(ngx_autocert_account_t *acct, ngx_str_t *dst,
    ngx_str_t *src)
{
    dst->data = ngx_pnalloc(acct->pool, src->len);
    if (dst->data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(dst->data, src->data, src->len);
    dst->len = src->len;
    return NGX_OK;
}


ngx_int_t
ngx_autocert_account_register(ngx_autocert_account_t *acct)
{
    /* Reset run state so a reused acct struct can't suppress the terminal
     * handler or surface a stale kid. (The caller is expected to pcalloc it,
     * but don't depend on that.) */
    acct->done = 0;
    acct->register_retried = 0;
    acct->key = NULL;
    ngx_str_null(&acct->kid);
    ngx_str_null(&acct->new_nonce_url);
    ngx_str_null(&acct->new_account_url);
    ngx_str_null(&acct->nonce);

    acct->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, acct->log);
    if (acct->pool == NULL) {
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, acct->log, 0,
                   "autocert: account register start, directory \"%V\"",
                   &acct->directory_url);

    if (ngx_autocert_account_load_key(acct) != NGX_OK) {
        ngx_destroy_pool(acct->pool);
        acct->pool = NULL;
        return NGX_ERROR;
    }

    /* Step 1: fetch the directory to discover the endpoint URLs. */
    {
        ngx_str_t  get = ngx_string("GET");
        ngx_str_t  empty = ngx_null_string;

        if (ngx_autocert_account_start(acct, &get, &acct->directory_url,
                                       &empty, &empty,
                                       ngx_autocert_account_directory_done)
            != NGX_OK)
        {
            /* key was already loaded/generated above — free it too */
            ngx_autocert_account_free(acct);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/*
 * Load the account key from <key_path>, or generate + persist one if the file
 * is absent. Stored as unencrypted PKCS#8 PEM with 0600 perms (helper is the
 * only reader). On any error returns NGX_ERROR.
 */
static ngx_int_t
ngx_autocert_account_load_key(ngx_autocert_account_t *acct)
{
    ngx_file_t   file;
    ngx_str_t    pem;
    ssize_t      n;
    ngx_int_t    rc;

    int          dfd;
    const char  *leaf;

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = acct->key_path;
    file.log = acct->log;

    /* TOCTOU: pin the parent dir (full chain walked component-by-component),
     * open the leaf relative to it. O_NOFOLLOW on every component + the leaf:
     * never read a key through a planted symlink at any path component. The fd
     * is held across the ENOENT->save path so the directory the key is created
     * in is provably the same inode we just probed (no swap window between the
     * absence check and the O_EXCL create). */
    dfd = ngx_autocert_account_open_keydir(acct, &leaf);
    if (dfd == -1) {
        return NGX_ERROR;
    }
    file.fd = openat(dfd, leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

    if (file.fd == NGX_INVALID_FILE) {
        ngx_err_t  err = ngx_errno;     /* close(dfd) below must not clobber it */

        if (err != NGX_ENOENT) {
            (void) close(dfd);
            ngx_log_error(NGX_LOG_ERR, acct->log, err,
                          "autocert: open account key \"%V\" failed",
                          &acct->key_path);
            return NGX_ERROR;
        }

        /* absent -> generate + persist into the SAME pinned dir fd. */
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, acct->log, 0,
                       "autocert: account key \"%V\" absent, generating "
                       "(key_type %ui)", &acct->key_path, acct->key_type);
        acct->key = ngx_http_autocert_key_generate(acct->key_type);
        if (acct->key == NULL) {
            (void) close(dfd);
            ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                          "autocert: account key generation failed");
            return NGX_ERROR;
        }
        if (ngx_autocert_account_save_key(acct, dfd, leaf) != NGX_OK) {
            (void) close(dfd);
            ngx_http_autocert_key_free(acct->key);
            acct->key = NULL;
            return NGX_ERROR;
        }
        (void) close(dfd);
        return NGX_OK;
    }

    (void) close(dfd);

    /* present -> read whole file, parse PEM */
    {
        ngx_file_info_t  fi;

        if (ngx_fd_info(file.fd, &fi) == NGX_FILE_ERROR
            || ngx_file_size(&fi) <= 0
            || ngx_file_size(&fi) > 64 * 1024)
        {
            ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                          "autocert: account key \"%V\" bad size",
                          &acct->key_path);
            ngx_close_file(file.fd);
            return NGX_ERROR;
        }

        /* Must be a plain file owned tightly: reject anything with group/other
         * permission bits set (the private key must stay 0600). */
        if (!S_ISREG(fi.st_mode)) {
            ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                          "autocert: account key \"%V\" is not a regular file",
                          &acct->key_path);
            ngx_close_file(file.fd);
            return NGX_ERROR;
        }
        if (fi.st_mode & (S_IRWXG | S_IRWXO)) {
            ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                          "autocert: account key \"%V\" has group/other "
                          "permissions (must be 0600)", &acct->key_path);
            ngx_close_file(file.fd);
            return NGX_ERROR;
        }
        if (fi.st_uid != geteuid()) {
            ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                          "autocert: account key \"%V\" is not owned by "
                          "the helper user", &acct->key_path);
            ngx_close_file(file.fd);
            return NGX_ERROR;
        }
        pem.len = (size_t) ngx_file_size(&fi);
    }

    pem.data = ngx_pnalloc(acct->pool, pem.len);
    if (pem.data == NULL) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, pem.data, pem.len, 0);
    ngx_close_file(file.fd);

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, acct->log, 0,
                   "autocert: read account key PEM from \"%V\", %z bytes",
                   &acct->key_path, n);

    if (n != (ssize_t) pem.len) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: short read on account key \"%V\"",
                      &acct->key_path);
        return NGX_ERROR;
    }

    rc = ngx_http_autocert_key_from_pem(&pem, &acct->key);
    if (rc != NGX_OK || acct->key == NULL) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: parse account key \"%V\" failed",
                      &acct->key_path);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, acct->log, 0,
                  "autocert: loaded account key from \"%V\"", &acct->key_path);
    return NGX_OK;
}


/*
 * Persist the account key. dfd is the caller's pinned parent dir fd and leaf the
 * single-component key filename relative to it; the SAME fd was used for the
 * load-time absence check, so there is no swap window between probe and create,
 * and the dir fsync below is provably of the inode we wrote into. The caller
 * owns dfd and closes it; this function never closes it.
 */
static ngx_int_t
ngx_autocert_account_save_key(ngx_autocert_account_t *acct, int dfd,
    const char *leaf)
{
    ngx_str_t    pem;
    ngx_fd_t     fd;
    size_t       off;

    if (ngx_http_autocert_key_to_pem(acct->pool, acct->key, &pem) != NGX_OK) {
        return NGX_ERROR;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_CORE, acct->log, 0,
                   "autocert: persisting account key to \"%V\", %uz PEM bytes",
                   &acct->key_path, pem.len);

    /*
     * Exclusive create at 0600, no symlink follow: never world-readable, never
     * clobber an existing key, never be redirected through a planted symlink at
     * the leaf (parent chain is pinned by dfd). O_EXCL is the point — this is
     * only reached when the load open returned ENOENT, so the file should not
     * exist; if it now does (race) we bail rather than overwrite.
     */
    fd = openat(dfd, leaf,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                      "autocert: create account key \"%V\" failed",
                      &acct->key_path);
        return NGX_ERROR;
    }

    for (off = 0; off < pem.len; /* void */) {
        ssize_t  n = write(fd, pem.data + off, pem.len - off);

        if (n < 0) {
            if (ngx_errno == NGX_EINTR) {
                continue;
            }
            ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                          "autocert: write account key \"%V\" failed",
                          &acct->key_path);
            ngx_close_file(fd);
            (void) unlinkat(dfd, leaf, 0);                /* no partial key */
            return NGX_ERROR;
        }
        off += (size_t) n;
    }

    /* Durably persist before close: the O_EXCL load path only regenerates on
     * ENOENT, so a crash that left a zero/partial key would be refused forever.
     * fsync the file (EINTR-retried). */
    while (fsync(fd) != 0) {
        if (ngx_errno == NGX_EINTR) {
            continue;
        }
        ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                      "autocert: fsync account key \"%V\" failed",
                      &acct->key_path);
        ngx_close_file(fd);
        (void) unlinkat(dfd, leaf, 0);
        return NGX_ERROR;
    }

    if (ngx_close_file(fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                      "autocert: close account key \"%V\" failed",
                      &acct->key_path);
        (void) unlinkat(dfd, leaf, 0);
        return NGX_ERROR;
    }

    /* Best-effort: fsync the containing directory (the pinned dfd) so the new
     * key's dentry is durable too. The key file itself is already fully
     * written + fsynced + closed, so a dir fsync failure (e.g. a filesystem
     * that rejects directory fsync) must NOT delete it or fail the save. */
    while (fsync(dfd) != 0) {
        if (ngx_errno == NGX_EINTR) {
            continue;
        }
        ngx_log_error(NGX_LOG_WARN, acct->log, ngx_errno,
                      "autocert: fsync key dir failed (best-effort)");
        break;
    }

    ngx_log_error(NGX_LOG_NOTICE, acct->log, 0,
                  "autocert: generated + saved account key \"%V\"",
                  &acct->key_path);
    return NGX_OK;
}


/*
 * Allocate a per-step request on its own pool and launch it. The request pool
 * is the request's `data` so the step handler can destroy it after copying out
 * what it needs.
 */
static ngx_int_t
ngx_autocert_account_start(ngx_autocert_account_t *acct, ngx_str_t *method,
    ngx_str_t *url, ngx_str_t *body, ngx_str_t *ctype,
    ngx_autocert_acme_handler_pt handler)
{
    ngx_pool_t                   *pool;
    ngx_autocert_acme_request_t  *req;

    pool = ngx_create_pool(NGX_MIN_POOL_SIZE, acct->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    req = ngx_pcalloc(pool, sizeof(ngx_autocert_acme_request_t));
    if (req == NULL) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    req->client = acct->client;
    req->pool = pool;
    req->log = acct->log;
    req->method = *method;
    req->url = *url;
    req->body = *body;
    req->content_type = *ctype;
    req->handler = handler;
    req->data = acct;

    if (ngx_autocert_acme_request(req) != NGX_OK) {
        ngx_destroy_pool(pool);
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_autocert_account_directory_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_account_t     *acct = req->data;
    ngx_autocert_json_value_t  *root;
    ngx_str_t                   nn, na;
    ngx_str_t                   scheme = ngx_string("https://");
    ngx_int_t                   ok = NGX_ERROR;

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        if (root != NULL
            && ngx_autocert_json_object_str(root, "newNonce", &nn) == NGX_OK
            && ngx_autocert_json_object_str(root, "newAccount", &na) == NGX_OK
            && nn.len > scheme.len
            && na.len > scheme.len
            && ngx_strncasecmp(nn.data, scheme.data, scheme.len) == 0
            && ngx_strncasecmp(na.data, scheme.data, scheme.len) == 0
            && ngx_autocert_account_dup(acct, &acct->new_nonce_url, &nn)
               == NGX_OK
            && ngx_autocert_account_dup(acct, &acct->new_account_url, &na)
               == NGX_OK)
        {
            ok = NGX_OK;
        }
    }

    ngx_destroy_pool(req->pool);

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: ACME directory missing/invalid endpoints");
        ngx_autocert_account_finish(acct, NGX_ERROR);
        return;
    }

    /* Step 2: GET newNonce; the value comes back as the Replay-Nonce header. */
    {
        ngx_str_t  get = ngx_string("GET");
        ngx_str_t  empty = ngx_null_string;

        if (ngx_autocert_account_start(acct, &get, &acct->new_nonce_url,
                                       &empty, &empty,
                                       ngx_autocert_account_nonce_done)
            != NGX_OK)
        {
            ngx_autocert_account_finish(acct, NGX_ERROR);
        }
    }
}


static void
ngx_autocert_account_nonce_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_account_t  *acct = req->data;
    ngx_str_t               *nonce;
    ngx_int_t                ok = NGX_ERROR;

    /* newNonce replies 200 (GET) or 204 (HEAD); either way the nonce is in the
     * Replay-Nonce header. */
    if (rc == NGX_OK && (req->status == 200 || req->status == 204)) {
        nonce = ngx_autocert_acme_header(req, "Replay-Nonce");
        if (nonce != NULL && nonce->len > 0
            && ngx_autocert_account_dup(acct, &acct->nonce, nonce) == NGX_OK)
        {
            ok = NGX_OK;
        }
    }

    ngx_destroy_pool(req->pool);

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: no Replay-Nonce from newNonce");
        ngx_autocert_account_finish(acct, NGX_ERROR);
        return;
    }

    /* Step 3: POST newAccount. */
    if (ngx_autocert_account_post_account(acct) != NGX_OK) {
        ngx_autocert_account_finish(acct, NGX_ERROR);
    }
}


/*
 * Build the External Account Binding object (RFC 8555 §7.3.4): a flattened-JSON
 * JWS whose protected header is {"alg":"HS256","kid":<eab_kid>,"url":<newAccount
 * URL>}, whose payload is the account-key public JWK (the SAME `jwk` string the
 * outer newAccount request embeds), and whose signature is HMAC-SHA256 over
 * "<b64(protected)>.<b64(payload)>" keyed by the base64url-decoded CA HMAC key.
 * Emits the JWS JSON into *out (acct->pool). Caller splices it into the
 * newAccount payload as "externalAccountBinding".
 */
static ngx_int_t
ngx_autocert_account_build_eab(ngx_autocert_account_t *acct, ngx_str_t *jwk,
    ngx_str_t *out)
{
    ngx_str_t   protected, hmac_key, b64_protected, b64_payload, signing_input;
    ngx_str_t   mac, b64_sig;
    u_char     *p;
    size_t      size;

    /* eab_kid is operator-supplied but lands inside the signed protected JSON;
     * new_account_url is server-supplied and already json_safe-checked by the
     * caller. Reject quote/backslash/control in the kid the same way. */
    if (!ngx_autocert_account_json_safe(&acct->eab_kid)) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: unsafe character in autocert_eab_kid");
        return NGX_ERROR;
    }

    /* decode the base64url HMAC key handed out by the CA. */
    if (ngx_http_autocert_base64url_decode(acct->pool, &acct->eab_hmac_key,
                                           &hmac_key)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: autocert_eab_hmac_key is not valid base64url");
        return NGX_ERROR;
    }
    if (hmac_key.len == 0) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: autocert_eab_hmac_key decodes to zero bytes");
        return NGX_ERROR;
    }

    /* protected = {"alg":"HS256","kid":"<kid>","url":"<newAccount url>"} */
    size = sizeof("{\"alg\":\"HS256\",\"kid\":\"\",\"url\":\"\"}") - 1
           + acct->eab_kid.len + acct->new_account_url.len;
    protected.data = ngx_pnalloc(acct->pool, size);
    if (protected.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(protected.data, "{\"alg\":\"HS256\",\"kid\":\"",
                   sizeof("{\"alg\":\"HS256\",\"kid\":\"") - 1);
    p = ngx_cpymem(p, acct->eab_kid.data, acct->eab_kid.len);
    p = ngx_cpymem(p, "\",\"url\":\"", sizeof("\",\"url\":\"") - 1);
    p = ngx_cpymem(p, acct->new_account_url.data, acct->new_account_url.len);
    p = ngx_cpymem(p, "\"}", sizeof("\"}") - 1);
    protected.len = p - protected.data;

    if (ngx_http_autocert_base64url_encode(acct->pool, &protected,
                                           &b64_protected)
        != NGX_OK
        || ngx_http_autocert_base64url_encode(acct->pool, jwk, &b64_payload)
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* signing input = b64(protected) "." b64(payload) */
    signing_input.len = b64_protected.len + 1 + b64_payload.len;
    signing_input.data = ngx_pnalloc(acct->pool, signing_input.len);
    if (signing_input.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(signing_input.data, b64_protected.data, b64_protected.len);
    *p++ = '.';
    p = ngx_cpymem(p, b64_payload.data, b64_payload.len);

    if (ngx_http_autocert_hmac_sha256(acct->pool, &hmac_key, &signing_input,
                                      &mac)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: EAB HMAC-SHA256 failed");
        return NGX_ERROR;
    }

    if (ngx_http_autocert_base64url_encode(acct->pool, &mac, &b64_sig)
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* {"protected":"<>","payload":"<>","signature":"<>"} */
    size = sizeof("{\"protected\":\"\",\"payload\":\"\",\"signature\":\"\"}") - 1
           + b64_protected.len + b64_payload.len + b64_sig.len;
    out->data = ngx_pnalloc(acct->pool, size);
    if (out->data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(out->data, "{\"protected\":\"",
                   sizeof("{\"protected\":\"") - 1);
    p = ngx_cpymem(p, b64_protected.data, b64_protected.len);
    p = ngx_cpymem(p, "\",\"payload\":\"", sizeof("\",\"payload\":\"") - 1);
    p = ngx_cpymem(p, b64_payload.data, b64_payload.len);
    p = ngx_cpymem(p, "\",\"signature\":\"", sizeof("\",\"signature\":\"") - 1);
    p = ngx_cpymem(p, b64_sig.data, b64_sig.len);
    p = ngx_cpymem(p, "\"}", sizeof("\"}") - 1);
    out->len = p - out->data;

    return NGX_OK;
}


/*
 * Build and send the newAccount JWS POST. The protected header carries the
 * public JWK (newAccount is a JWK-signed request, not kid-signed), the alg, the
 * nonce and the target URL; the payload agrees to the ToS.
 */
static ngx_int_t
ngx_autocert_account_post_account(ngx_autocert_account_t *acct)
{
    ngx_str_t    jwk, protected, jws;
    ngx_str_t    payload = ngx_string("{\"termsOfServiceAgreed\":true}");
    ngx_str_t    ctype = ngx_string("application/jose+json");
    ngx_str_t    eab;
    ngx_str_t    post = ngx_string("POST");
    const char  *alg;
    u_char      *p;
    size_t       size;

    alg = ngx_http_autocert_jws_alg(acct->key);
    if (alg == NULL) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: unsupported account key curve");
        return NGX_ERROR;
    }

    if (ngx_http_autocert_jwk_public(acct->pool, acct->key, &jwk) != NGX_OK) {
        return NGX_ERROR;
    }

    /* nonce (Replay-Nonce header) and new_account_url (directory JSON) are
     * server-controlled and spliced verbatim into the signed protected header
     * below; reject `"`/`\`/control bytes here exactly as the kid-signed path
     * does (ngx_autocert_account_send_post), so a hostile response can't break
     * out of or inject into the protected JSON. */
    if (!ngx_autocert_account_json_safe(&acct->nonce)
        || !ngx_autocert_account_json_safe(&acct->new_account_url))
    {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: unsafe character in ACME nonce or directory "
                      "newAccount URL");
        return NGX_ERROR;
    }

    /*
     * The newAccount payload carries ToS agreement plus two optional members:
     *  - contact:["mailto:<email>"] (audit LOW) when an account email is set;
     *  - externalAccountBinding:<JWS> (M15, RFC 8555 §7.3.4) when EAB is set.
     * EAB is sent ONLY on newAccount — kid-signed POSTs never carry it. Both
     * the email and new_account_url (json_safe above) land in signed JSON, so
     * the email is json_safe-checked too. Build the payload once with whichever
     * members are present:
     *   {"termsOfServiceAgreed":true[,"contact":[...]][,"externalAccountBinding":...]}
     */
    if (acct->email.len != 0 || acct->eab_kid.len != 0) {
        ngx_str_t  contact = ngx_null_string;
        size_t     size;

        if (acct->email.len != 0) {
            if (!ngx_autocert_account_json_safe(&acct->email)) {
                ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                              "autocert: unsafe character in account email");
                return NGX_ERROR;
            }
            contact.data = ngx_pnalloc(acct->pool,
                sizeof(",\"contact\":[\"mailto:\"]") - 1 + acct->email.len);
            if (contact.data == NULL) {
                return NGX_ERROR;
            }
            p = ngx_cpymem(contact.data, ",\"contact\":[\"mailto:",
                           sizeof(",\"contact\":[\"mailto:") - 1);
            p = ngx_cpymem(p, acct->email.data, acct->email.len);
            p = ngx_cpymem(p, "\"]", sizeof("\"]") - 1);
            contact.len = p - contact.data;
        }

        if (acct->eab_kid.len != 0) {
            if (ngx_autocert_account_build_eab(acct, &jwk, &eab) != NGX_OK) {
                return NGX_ERROR;
            }
        } else {
            ngx_str_null(&eab);
        }

        size = sizeof("{\"termsOfServiceAgreed\":true}") - 1 + contact.len
               + (eab.len ? sizeof(",\"externalAccountBinding\":") - 1 + eab.len
                          : 0);
        payload.data = ngx_pnalloc(acct->pool, size);
        if (payload.data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_cpymem(payload.data, "{\"termsOfServiceAgreed\":true",
                       sizeof("{\"termsOfServiceAgreed\":true") - 1);
        if (contact.len) {
            p = ngx_cpymem(p, contact.data, contact.len);
        }
        if (eab.len) {
            p = ngx_cpymem(p, ",\"externalAccountBinding\":",
                           sizeof(",\"externalAccountBinding\":") - 1);
            p = ngx_cpymem(p, eab.data, eab.len);
        }
        *p++ = '}';
        payload.len = p - payload.data;
    }

    /* protected = {"alg":"<alg>","jwk":<jwk>,"nonce":"<nonce>","url":"<url>"} */
    size = sizeof("{\"alg\":\"\",\"jwk\":,\"nonce\":\"\",\"url\":\"\"}") - 1
           + ngx_strlen(alg) + jwk.len + acct->nonce.len
           + acct->new_account_url.len;

    protected.data = ngx_pnalloc(acct->pool, size);
    if (protected.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(protected.data, "{\"alg\":\"", sizeof("{\"alg\":\"") - 1);
    p = ngx_cpymem(p, alg, ngx_strlen(alg));
    p = ngx_cpymem(p, "\",\"jwk\":", sizeof("\",\"jwk\":") - 1);
    p = ngx_cpymem(p, jwk.data, jwk.len);
    p = ngx_cpymem(p, ",\"nonce\":\"", sizeof(",\"nonce\":\"") - 1);
    p = ngx_cpymem(p, acct->nonce.data, acct->nonce.len);
    p = ngx_cpymem(p, "\",\"url\":\"", sizeof("\",\"url\":\"") - 1);
    p = ngx_cpymem(p, acct->new_account_url.data, acct->new_account_url.len);
    p = ngx_cpymem(p, "\"}", sizeof("\"}") - 1);
    protected.len = p - protected.data;

    if (ngx_http_autocert_jws_sign(acct->pool, acct->key, &protected, &payload,
                                   &jws)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: newAccount JWS signing failed");
        return NGX_ERROR;
    }

    return ngx_autocert_account_start(acct, &post, &acct->new_account_url,
                                      &jws, &ctype,
                                      ngx_autocert_account_register_done);
}


static void
ngx_autocert_account_register_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_account_t  *acct = req->data;
    ngx_str_t               *loc;
    ngx_int_t                ok = NGX_ERROR;

    /* 201 Created (new) or 200 OK (existing account, returnExisting). The kid
     * is the account URL in the Location header. */
    if (rc == NGX_OK && (req->status == 201 || req->status == 200)) {
        loc = ngx_autocert_acme_header(req, "Location");
        if (loc != NULL && loc->len > 0
            && ngx_autocert_account_dup(acct, &acct->kid, loc) == NGX_OK)
        {
            ngx_str_t  *nonce;

            /* Capture the fresh Replay-Nonce so the first kid-signed POST
             * (newOrder) doesn't reuse the spent registration nonce and burn
             * its only badNonce retry. A missing header isn't fatal — the
             * kid-path refetches on badNonce. */
            nonce = ngx_autocert_acme_header(req, "Replay-Nonce");
            if (nonce != NULL && nonce->len > 0) {
                (void) ngx_autocert_account_set_nonce(acct, nonce);
            }

            ok = NGX_OK;
        }
    }

    /*
     * newAccount is a one-shot POST (its own JWK-signed path, not the M6a
     * kid-signed primitive), so it didn't share that path's badNonce retry.
     * A fresh ACME server occasionally rejects the first nonce (badNonce) —
     * re-fetch newNonce and re-POST newAccount once. (This is why CI previously
     * needed PEBBLE_WFE_NONCEREJECT=0.)
     */
    if (ok != NGX_OK && !acct->register_retried
        && ngx_autocert_account_is_bad_nonce(req))
    {
        ngx_str_t  get = ngx_string("GET");
        ngx_str_t  empty = ngx_null_string;

        acct->register_retried = 1;
        ngx_destroy_pool(req->pool);

        ngx_log_error(NGX_LOG_NOTICE, acct->log, 0,
                      "autocert: newAccount badNonce, re-fetching nonce and "
                      "retrying");

        if (ngx_autocert_account_start(acct, &get, &acct->new_nonce_url,
                                       &empty, &empty,
                                       ngx_autocert_account_register_renonce_done)
            != NGX_OK)
        {
            ngx_autocert_account_finish(acct, NGX_ERROR);
        }
        return;
    }

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: newAccount failed, status %ui", req->status);
    }

    ngx_destroy_pool(req->pool);
    ngx_autocert_account_finish(acct, ok);
}


/*
 * Completion of the newNonce GET issued for a newAccount badNonce retry: stash
 * the fresh Replay-Nonce and re-POST newAccount. Mirrors nonce_done but routes
 * back to the register POST instead of the first-time path.
 */
static void
ngx_autocert_account_register_renonce_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_account_t  *acct = req->data;
    ngx_str_t               *nonce;
    ngx_int_t                ok = NGX_ERROR;

    if (rc == NGX_OK && (req->status == 200 || req->status == 204)) {
        nonce = ngx_autocert_acme_header(req, "Replay-Nonce");
        if (nonce != NULL && nonce->len > 0
            && ngx_autocert_account_dup(acct, &acct->nonce, nonce) == NGX_OK)
        {
            ok = NGX_OK;
        }
    }

    ngx_destroy_pool(req->pool);

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: no Replay-Nonce on newAccount retry");
        ngx_autocert_account_finish(acct, NGX_ERROR);
        return;
    }

    if (ngx_autocert_account_post_account(acct) != NGX_OK) {
        ngx_autocert_account_finish(acct, NGX_ERROR);
    }
}


/* --- M6a: kid-signed POST primitive ------------------------------------- */

static ngx_int_t ngx_autocert_account_send_post(ngx_autocert_account_t *acct);
static void ngx_autocert_account_post_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc);
static void ngx_autocert_account_renonce_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc);
static ngx_uint_t ngx_autocert_account_is_bad_nonce(
    ngx_autocert_acme_request_t *req);
static void ngx_autocert_account_post_fail(ngx_autocert_account_t *acct);
static ngx_int_t ngx_autocert_account_set_nonce(ngx_autocert_account_t *acct,
    ngx_str_t *nonce);


/*
 * The kid/nonce/url bytes we embed verbatim in the protected JWS JSON come from
 * ACME responses (Location/Replay-Nonce headers, directory URLs). They must not
 * contain a JSON-string-breaking byte: a control char (< 0x20), a double quote,
 * or a backslash would corrupt the protected header or inject a field. ACME
 * tokens/URLs/nonces never legitimately contain these, so reject rather than
 * escape — a value with them is a malformed/hostile server response.
 */
static ngx_uint_t
ngx_autocert_account_json_safe(ngx_str_t *s)
{
    size_t  i;

    for (i = 0; i < s->len; i++) {
        u_char c = s->data[i];
        if (c < 0x20 || c == '"' || c == '\\') {
            return 0;
        }
    }
    return 1;
}


/*
 * Replace the account's current nonce with `nonce`, copied into a dedicated
 * pool that is reset (not grown) on every refresh — so the long-lived session
 * pool doesn't accumulate one dead nonce per signed POST/poll/retry.
 */
static ngx_int_t
ngx_autocert_account_set_nonce(ngx_autocert_account_t *acct, ngx_str_t *nonce)
{
    if (acct->nonce_pool == NULL) {
        acct->nonce_pool = ngx_create_pool(NGX_MIN_POOL_SIZE, acct->log);
        if (acct->nonce_pool == NULL) {
            return NGX_ERROR;
        }
    } else {
        ngx_reset_pool(acct->nonce_pool);
    }

    acct->nonce.data = ngx_pnalloc(acct->nonce_pool, nonce->len);
    if (acct->nonce.data == NULL) {
        ngx_str_null(&acct->nonce);
        return NGX_ERROR;
    }
    ngx_memcpy(acct->nonce.data, nonce->data, nonce->len);
    acct->nonce.len = nonce->len;
    return NGX_OK;
}


ngx_int_t
ngx_autocert_account_post(ngx_autocert_account_t *acct, ngx_str_t *url,
    ngx_str_t *payload, ngx_autocert_acme_handler_pt handler, void *data)
{
    if (acct->kid.len == 0 || acct->key == NULL) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: kid-signed POST before account ready");
        return NGX_ERROR;
    }

    /* One in-flight kid-signed POST per account: the POST state lives on the
     * account struct, so a second concurrent call would clobber the first. The
     * order state machine is strictly sequential, so this is an invariant, not
     * a queue — reject a violation loudly rather than corrupt state. */
    if (acct->post_pool != NULL) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: concurrent kid-signed POST rejected");
        return NGX_ERROR;
    }

    /* Reject a URL that would break the protected JSON (the payload is opaque
     * and base64url-encoded by the JWS, so only the URL needs the check here;
     * kid/nonce are checked at sign time). */
    if (!ngx_autocert_account_json_safe(url)) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: unsafe bytes in POST url");
        return NGX_ERROR;
    }

    /* Each signed POST gets its own pool, freed in the internal completion
     * before the caller's handler runs. */
    acct->post_pool = ngx_create_pool(NGX_MIN_POOL_SIZE, acct->log);
    if (acct->post_pool == NULL) {
        return NGX_ERROR;
    }

    acct->post_url.data = ngx_pnalloc(acct->post_pool, url->len);
    acct->post_payload.data = ngx_pnalloc(acct->post_pool, payload->len);
    if (acct->post_url.data == NULL
        || (payload->len != 0 && acct->post_payload.data == NULL))
    {
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
        return NGX_ERROR;
    }
    ngx_memcpy(acct->post_url.data, url->data, url->len);
    acct->post_url.len = url->len;
    ngx_memcpy(acct->post_payload.data, payload->data, payload->len);
    acct->post_payload.len = payload->len;

    acct->post_handler = handler;
    acct->post_data = data;
    acct->post_retried = 0;

    /* Reserve the last-resort failure req/pool NOW, while we can still fail
     * synchronously (the caller handles a NGX_ERROR return without needing a
     * req). Once the POST is in flight, the only way to report failure is via
     * the handler, which must receive a non-NULL req — so this allocation must
     * not be deferred to the failure path where OOM could leave us with none. */
    acct->post_fail_pool = ngx_create_pool(NGX_MIN_POOL_SIZE, acct->log);
    if (acct->post_fail_pool == NULL) {
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
        return NGX_ERROR;
    }
    acct->post_fail_req = ngx_pcalloc(acct->post_fail_pool,
                                      sizeof(ngx_autocert_acme_request_t));
    if (acct->post_fail_req == NULL) {
        ngx_destroy_pool(acct->post_fail_pool);
        acct->post_fail_pool = NULL;
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
        return NGX_ERROR;
    }
    acct->post_fail_req->pool = acct->post_fail_pool;
    acct->post_fail_req->log = acct->log;

    if (ngx_autocert_account_send_post(acct) != NGX_OK) {
        ngx_destroy_pool(acct->post_fail_pool);
        acct->post_fail_pool = NULL;
        acct->post_fail_req = NULL;
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


/*
 * Build the kid-signed JWS for the pending post_url/post_payload with the
 * account's current nonce and send it. Reused for the badNonce retry.
 */
static ngx_int_t
ngx_autocert_account_send_post(ngx_autocert_account_t *acct)
{
    ngx_str_t    protected, jws;
    ngx_str_t    ctype = ngx_string("application/jose+json");
    ngx_str_t    post = ngx_string("POST");
    const char  *alg;
    u_char      *p;
    size_t       size;

    alg = ngx_http_autocert_jws_alg(acct->key);
    if (alg == NULL) {
        return NGX_ERROR;
    }

    /* kid and nonce are embedded verbatim in the protected JSON; reject any
     * value that could break the string (the url was checked at submit). */
    if (!ngx_autocert_account_json_safe(&acct->kid)
        || !ngx_autocert_account_json_safe(&acct->nonce))
    {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: unsafe bytes in kid/nonce");
        return NGX_ERROR;
    }

    /* protected = {"alg":"<alg>","kid":"<kid>","nonce":"<nonce>","url":"<url>"} */
    size = sizeof("{\"alg\":\"\",\"kid\":\"\",\"nonce\":\"\",\"url\":\"\"}") - 1
           + ngx_strlen(alg) + acct->kid.len + acct->nonce.len
           + acct->post_url.len;

    protected.data = ngx_pnalloc(acct->post_pool, size);
    if (protected.data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(protected.data, "{\"alg\":\"", sizeof("{\"alg\":\"") - 1);
    p = ngx_cpymem(p, alg, ngx_strlen(alg));
    p = ngx_cpymem(p, "\",\"kid\":\"", sizeof("\",\"kid\":\"") - 1);
    p = ngx_cpymem(p, acct->kid.data, acct->kid.len);
    p = ngx_cpymem(p, "\",\"nonce\":\"", sizeof("\",\"nonce\":\"") - 1);
    p = ngx_cpymem(p, acct->nonce.data, acct->nonce.len);
    p = ngx_cpymem(p, "\",\"url\":\"", sizeof("\",\"url\":\"") - 1);
    p = ngx_cpymem(p, acct->post_url.data, acct->post_url.len);
    p = ngx_cpymem(p, "\"}", sizeof("\"}") - 1);
    protected.len = p - protected.data;

    if (ngx_http_autocert_jws_sign(acct->post_pool, acct->key, &protected,
                                   &acct->post_payload, &jws)
        != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: kid-signed JWS signing failed");
        return NGX_ERROR;
    }

    /* The signed POST request runs on its own request pool (child of nothing —
     * a fresh pool per request, as account_start does). */
    {
        ngx_pool_t                   *pool;
        ngx_autocert_acme_request_t  *req;

        pool = ngx_create_pool(NGX_MIN_POOL_SIZE, acct->log);
        if (pool == NULL) {
            return NGX_ERROR;
        }

        req = ngx_pcalloc(pool, sizeof(ngx_autocert_acme_request_t));
        if (req == NULL) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }

        req->client = acct->client;
        req->pool = pool;
        req->log = acct->log;
        req->method = post;
        req->content_type = ctype;
        req->handler = ngx_autocert_account_post_done;
        req->data = acct;

        /* Copy url + signed body into the REQUEST pool so the request (and the
         * req handed to the caller's completion handler) does not alias the
         * per-POST signing pool, which is destroyed before that handler runs. */
        req->url.data = ngx_pnalloc(pool, acct->post_url.len);
        req->body.data = ngx_pnalloc(pool, jws.len);
        if (req->url.data == NULL || (jws.len != 0 && req->body.data == NULL)) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }
        ngx_memcpy(req->url.data, acct->post_url.data, acct->post_url.len);
        req->url.len = acct->post_url.len;
        ngx_memcpy(req->body.data, jws.data, jws.len);
        req->body.len = jws.len;

        if (ngx_autocert_acme_request(req) != NGX_OK) {
            ngx_destroy_pool(pool);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


/* True if the response is an ACME badNonce error (type ends with
 * ":badNonce"). ACME errors are 4xx with a problem+json body. */
static ngx_uint_t
ngx_autocert_account_is_bad_nonce(ngx_autocert_acme_request_t *req)
{
    ngx_autocert_json_value_t  *root;
    ngx_str_t                   type;
    static const u_char         suffix[] = ":badNonce";

    if (req->status < 400 || req->body_out.len == 0) {
        return 0;
    }

    root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                   req->body_out.len);
    if (root == NULL
        || ngx_autocert_json_object_str(root, "type", &type) != NGX_OK)
    {
        return 0;
    }

    if (type.len < sizeof(suffix) - 1) {
        return 0;
    }

    return ngx_strncmp(type.data + type.len - (sizeof(suffix) - 1),
                       suffix, sizeof(suffix) - 1) == 0;
}


/*
 * Deliver a terminal failure to the caller's post handler. The contract gives
 * the caller a non-NULL req carrying its own post_data (so its handler can read
 * req->data and finish its state machine); status 0 marks "no HTTP response".
 * The caller owns and destroys req->pool, as on the success path.
 */
static void
ngx_autocert_account_post_fail(ngx_autocert_account_t *acct)
{
    ngx_autocert_acme_handler_pt  handler = acct->post_handler;
    void                         *data = acct->post_data;
    ngx_autocert_acme_request_t  *req;

    if (acct->post_pool) {
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
    }

    /* Hand back the failure req reserved at submit. It is always present once a
     * POST is in flight, so the caller's handler never sees NULL (which it
     * ignores, stalling the order). The caller now owns req->pool and destroys
     * it, as on the success path — so drop our pointers to it here. */
    req = acct->post_fail_req;
    acct->post_fail_req = NULL;
    acct->post_fail_pool = NULL;

    if (handler == NULL) {
        if (req != NULL) {
            ngx_destroy_pool(req->pool);
        }
        return;
    }

    if (req == NULL) {
        /* Should not happen: a POST is in flight => the req was reserved. */
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: no reserved failure req");
        handler(NULL, NGX_ERROR);
        return;
    }

    req->data = data;
    req->status = 0;

    handler(req, NGX_ERROR);
}


static void
ngx_autocert_account_post_done(ngx_autocert_acme_request_t *req, ngx_int_t rc)
{
    ngx_autocert_account_t  *acct = req->data;
    ngx_str_t               *nonce;

    /* Refresh the account nonce from any response that carries one (success or
     * error — ACME returns a fresh nonce on most replies). Stored in the
     * resettable nonce pool so nonces don't accumulate. */
    if (rc == NGX_OK) {
        nonce = ngx_autocert_acme_header(req, "Replay-Nonce");
        if (nonce != NULL && nonce->len > 0) {
            (void) ngx_autocert_account_set_nonce(acct, nonce);
        }
    }

    /* badNonce: re-fetch newNonce and retry the same POST once. */
    if (rc == NGX_OK && !acct->post_retried
        && ngx_autocert_account_is_bad_nonce(req))
    {
        acct->post_retried = 1;
        ngx_destroy_pool(req->pool);

        ngx_log_error(NGX_LOG_NOTICE, acct->log, 0,
                      "autocert: badNonce, re-fetching nonce and retrying POST");

        {
            ngx_pool_t                   *pool;
            ngx_autocert_acme_request_t  *nreq;
            ngx_str_t                     get = ngx_string("GET");

            pool = ngx_create_pool(NGX_MIN_POOL_SIZE, acct->log);
            if (pool == NULL) {
                ngx_autocert_account_post_fail(acct);
                return;
            }
            nreq = ngx_pcalloc(pool, sizeof(ngx_autocert_acme_request_t));
            if (nreq == NULL) {
                ngx_destroy_pool(pool);
                ngx_autocert_account_post_fail(acct);
                return;
            }
            nreq->client = acct->client;
            nreq->pool = pool;
            nreq->log = acct->log;
            nreq->method = get;
            nreq->url = acct->new_nonce_url;
            nreq->handler = ngx_autocert_account_renonce_done;
            nreq->data = acct;

            if (ngx_autocert_acme_request(nreq) != NGX_OK) {
                ngx_destroy_pool(pool);
                ngx_autocert_account_post_fail(acct);
            }
        }
        return;
    }

    /* Terminal success: hand the finished request to the caller, then it owns
     * req->pool (it must destroy it). Release the per-POST signing pool and the
     * unused reserved failure pool first. */
    if (acct->post_pool) {
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
    }
    if (acct->post_fail_pool) {
        ngx_destroy_pool(acct->post_fail_pool);
        acct->post_fail_pool = NULL;
        acct->post_fail_req = NULL;
    }

    /* The request carried acct as its data (this handler reads it); hand the
     * caller's own context back through req->data so the caller's handler sees
     * what it passed to ngx_autocert_account_post(). */
    req->data = acct->post_data;

    if (acct->post_handler) {
        acct->post_handler(req, rc);
    } else {
        ngx_destroy_pool(req->pool);
    }
}


static void
ngx_autocert_account_renonce_done(ngx_autocert_acme_request_t *req,
    ngx_int_t rc)
{
    ngx_autocert_account_t  *acct = req->data;
    ngx_str_t               *nonce;
    ngx_int_t                ok = NGX_ERROR;

    if (rc == NGX_OK && (req->status == 200 || req->status == 204)) {
        nonce = ngx_autocert_acme_header(req, "Replay-Nonce");
        if (nonce != NULL && nonce->len > 0
            && ngx_autocert_account_set_nonce(acct, nonce) == NGX_OK)
        {
            ok = NGX_OK;
        }
    }

    ngx_destroy_pool(req->pool);

    if (ok != NGX_OK || ngx_autocert_account_send_post(acct) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: badNonce retry failed");
        ngx_autocert_account_post_fail(acct);
    }
}


static void
ngx_autocert_account_finish(ngx_autocert_account_t *acct, ngx_int_t rc)
{
    if (acct->done) {
        return;
    }
    acct->done = 1;

    if (rc == NGX_OK) {
        ngx_log_error(NGX_LOG_NOTICE, acct->log, 0,
                      "autocert: ACME account registered, kid \"%V\"",
                      &acct->kid);
    }

    /*
     * The kid/nonce/url strings live in acct->pool; the caller still needs kid
     * after we return, so we do NOT destroy acct->pool here — it is released by
     * ngx_autocert_account_free() once the caller is done with the account.
     */
    if (acct->handler) {
        acct->handler(acct, rc);
    }
}


void
ngx_autocert_account_free(ngx_autocert_account_t *acct)
{
    if (acct->key) {
        ngx_http_autocert_key_free(acct->key);
        acct->key = NULL;
    }
    if (acct->nonce_pool) {
        ngx_destroy_pool(acct->nonce_pool);
        acct->nonce_pool = NULL;
    }
    /* In-flight POST pools (normally NULL when the account is freed — it is
     * freed only on register failure, before any kid POST — but release them
     * defensively so a future caller can't leak them). */
    if (acct->post_pool) {
        ngx_destroy_pool(acct->post_pool);
        acct->post_pool = NULL;
    }
    if (acct->post_fail_pool) {
        ngx_destroy_pool(acct->post_fail_pool);
        acct->post_fail_pool = NULL;
        acct->post_fail_req = NULL;
    }
    if (acct->pool) {
        ngx_destroy_pool(acct->pool);
        acct->pool = NULL;
    }
}
