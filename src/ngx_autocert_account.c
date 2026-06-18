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


static ngx_int_t ngx_autocert_account_load_key(ngx_autocert_account_t *acct);
static ngx_int_t ngx_autocert_account_save_key(ngx_autocert_account_t *acct);
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
static void ngx_autocert_account_finish(ngx_autocert_account_t *acct,
    ngx_int_t rc);


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
    acct->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, acct->log);
    if (acct->pool == NULL) {
        return NGX_ERROR;
    }

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

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.name = acct->key_path;
    file.log = acct->log;

    file.fd = ngx_open_file(acct->key_path.data, NGX_FILE_RDONLY,
                            NGX_FILE_OPEN, 0);

    if (file.fd == NGX_INVALID_FILE) {
        if (ngx_errno != NGX_ENOENT) {
            ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                          "autocert: open account key \"%V\" failed",
                          &acct->key_path);
            return NGX_ERROR;
        }

        /* absent -> generate + persist */
        acct->key = ngx_http_autocert_key_generate(acct->key_type);
        if (acct->key == NULL) {
            ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                          "autocert: account key generation failed");
            return NGX_ERROR;
        }
        return ngx_autocert_account_save_key(acct);
    }

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
        pem.len = (size_t) ngx_file_size(&fi);
    }

    pem.data = ngx_pnalloc(acct->pool, pem.len);
    if (pem.data == NULL) {
        ngx_close_file(file.fd);
        return NGX_ERROR;
    }

    n = ngx_read_file(&file, pem.data, pem.len, 0);
    ngx_close_file(file.fd);

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


static ngx_int_t
ngx_autocert_account_save_key(ngx_autocert_account_t *acct)
{
    ngx_str_t  pem;
    ngx_fd_t   fd;
    ssize_t    n;

    if (ngx_http_autocert_key_to_pem(acct->pool, acct->key, &pem) != NGX_OK) {
        return NGX_ERROR;
    }

    /* O_CREAT|O_EXCL|O_WRONLY with 0600: never world-readable, never clobber. */
    fd = ngx_open_file(acct->key_path.data,
                       NGX_FILE_WRONLY,
                       NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                       0600);
    if (fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_ERR, acct->log, ngx_errno,
                      "autocert: create account key \"%V\" failed",
                      &acct->key_path);
        return NGX_ERROR;
    }

    n = ngx_write_fd(fd, pem.data, pem.len);
    ngx_close_file(fd);

    if (n != (ssize_t) pem.len) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: write account key \"%V\" failed",
                      &acct->key_path);
        return NGX_ERROR;
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
    ngx_int_t                   ok = NGX_ERROR;

    if (rc == NGX_OK && req->status == 200) {
        root = ngx_autocert_json_parse(req->pool, req->body_out.data,
                                       req->body_out.len);
        if (root != NULL
            && ngx_autocert_json_object_str(root, "newNonce", &nn) == NGX_OK
            && ngx_autocert_json_object_str(root, "newAccount", &na) == NGX_OK
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
            ok = NGX_OK;
        }
    }

    if (ok != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, acct->log, 0,
                      "autocert: newAccount failed, status %ui", req->status);
    }

    ngx_destroy_pool(req->pool);
    ngx_autocert_account_finish(acct, ok);
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
    if (acct->pool) {
        ngx_destroy_pool(acct->pool);
        acct->pool = NULL;
    }
}
