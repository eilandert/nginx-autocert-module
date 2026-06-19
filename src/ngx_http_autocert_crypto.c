/*
 * ngx_http_autocert_crypto — JOSE/ACME crypto primitives (M3).
 * See ngx_http_autocert_crypto.h for the contract.
 */

#include "ngx_http_autocert_crypto.h"

#include <limits.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>

#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
#error "nginx-autocert-module requires OpenSSL 3.0.0 or newer"
#endif


/* Per-curve facts: OpenSSL group NID, coordinate width, JOSE crv/alg names. */
typedef struct {
    int          nid;
    size_t       coord_len;   /* ceil(field_bits/8): 32 for P-256, 48 for P-384 */
    const char  *jwk_crv;     /* "P-256" / "P-384" */
    const char  *jws_alg;     /* "ES256" / "ES384" */
    const EVP_MD *(*md)(void);
} ngx_http_autocert_curve_t;


static const ngx_http_autocert_curve_t *
ngx_http_autocert_curve_by_id(ngx_uint_t curve)
{
    static const ngx_http_autocert_curve_t  p256 = {
        NID_X9_62_prime256v1, 32, "P-256", "ES256", EVP_sha256
    };
    static const ngx_http_autocert_curve_t  p384 = {
        NID_secp384r1, 48, "P-384", "ES384", EVP_sha384
    };

    switch (curve) {
    case NGX_HTTP_AUTOCERT_CRYPTO_P256:
        return &p256;
    case NGX_HTTP_AUTOCERT_CRYPTO_P384:
        return &p384;
    default:
        return NULL;
    }
}


/* Map a live EVP_PKEY back to its curve table by group NID. */
static const ngx_http_autocert_curve_t *
ngx_http_autocert_curve_of(EVP_PKEY *pkey)
{
    int  nid = NID_undef;

    if (pkey == NULL || EVP_PKEY_base_id(pkey) != EVP_PKEY_EC) {
        return NULL;
    }

    {
        char    gname[64];
        size_t  glen = 0;

        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                           gname, sizeof(gname), &glen) == 1)
        {
            nid = OBJ_sn2nid(gname);
            if (nid == NID_undef) {
                nid = OBJ_ln2nid(gname);
            }
        }
    }

    if (nid == NID_X9_62_prime256v1) {
        return ngx_http_autocert_curve_by_id(NGX_HTTP_AUTOCERT_CRYPTO_P256);
    }
    if (nid == NID_secp384r1) {
        return ngx_http_autocert_curve_by_id(NGX_HTTP_AUTOCERT_CRYPTO_P384);
    }

    return NULL;
}


EVP_PKEY *
ngx_http_autocert_key_generate(ngx_uint_t curve)
{
    const ngx_http_autocert_curve_t  *c;
    EVP_PKEY                         *pkey = NULL;
    EVP_PKEY_CTX                     *ctx;

    c = ngx_http_autocert_curve_by_id(curve);
    if (c == NULL) {
        return NULL;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, c->nid) != 1
        || EVP_PKEY_keygen(ctx, &pkey) != 1)
    {
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}


void
ngx_http_autocert_key_free(EVP_PKEY *pkey)
{
    EVP_PKEY_free(pkey);
}


ngx_int_t
ngx_http_autocert_key_to_pem(ngx_pool_t *pool, EVP_PKEY *pkey, ngx_str_t *out)
{
    BIO      *bio;
    char     *data;
    long      len;
    u_char   *buf;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NGX_ERROR;
    }

    if (PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL)
        != 1)
    {
        BIO_free(bio);
        return NGX_ERROR;
    }

    len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(pool, len);
    if (buf == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    ngx_memcpy(buf, data, len);
    out->data = buf;
    out->len = len;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "autocert: key PEM encoded, %O bytes", (off_t) len);

    BIO_free(bio);
    return NGX_OK;
}


ngx_int_t
ngx_http_autocert_cert_to_pem(ngx_pool_t *pool, X509 *cert, ngx_str_t *out)
{
    BIO      *bio;
    char     *data;
    long      len;
    u_char   *buf;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return NGX_ERROR;
    }

    if (PEM_write_bio_X509(bio, cert) != 1) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    buf = ngx_pnalloc(pool, len);
    if (buf == NULL) {
        BIO_free(bio);
        return NGX_ERROR;
    }

    ngx_memcpy(buf, data, len);
    out->data = buf;
    out->len = len;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "autocert: cert PEM encoded, %O bytes", (off_t) len);

    BIO_free(bio);
    return NGX_OK;
}


ngx_int_t
ngx_http_autocert_key_from_pem(ngx_str_t *pem, EVP_PKEY **out)
{
    BIO       *bio;
    EVP_PKEY  *pkey;

    /* BIO_new_mem_buf takes an int length; reject anything that would wrap. */
    if (pem->len > INT_MAX) {
        return NGX_ERROR;
    }

    bio = BIO_new_mem_buf(pem->data, (int) pem->len);
    if (bio == NULL) {
        return NGX_ERROR;
    }

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (pkey == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_autocert_curve_of(pkey) == NULL) {
        EVP_PKEY_free(pkey);
        return NGX_ERROR;
    }

    *out = pkey;
    return NGX_OK;
}


ngx_int_t
ngx_http_autocert_base64url_encode(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out)
{
    ngx_str_t  std;

    /*
     * ngx_base64_encoded_length is ((n+2)/3)*4; guard the input so that the
     * size_t arithmetic cannot wrap and under-allocate. The bound is generous
     * (all real inputs are tiny: keys, headers, payloads) — it only rejects
     * pathological lengths.
     */
    if (in->len > (size_t) NGX_MAX_SIZE_T_VALUE / 4 * 3 - 2) {
        return NGX_ERROR;
    }

    /* Standard base64 (with padding) sizing, then translate the alphabet. */
    std.len = ngx_base64_encoded_length(in->len);
    std.data = ngx_pnalloc(pool, std.len);
    if (std.data == NULL) {
        return NGX_ERROR;
    }

    ngx_encode_base64url(&std, in);

    *out = std;
    return NGX_OK;
}


ngx_int_t
ngx_http_autocert_base64url_decode(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out)
{
    ngx_str_t   dst;
    ngx_uint_t  i;
    u_char      ch;

    /*
     * Enforce the strict, no-padding base64url contract here: nginx's decoder
     * is permissive (accepts '=' padding and stops at the first non-alphabet
     * byte), which would silently truncate malformed CA input. Reject any byte
     * that is not in the RFC 4648 §5 URL-safe alphabet — in particular '='.
     */
    for (i = 0; i < in->len; i++) {
        ch = in->data[i];
        if (!((ch >= 'A' && ch <= 'Z')
              || (ch >= 'a' && ch <= 'z')
              || (ch >= '0' && ch <= '9')
              || ch == '-' || ch == '_'))
        {
            return NGX_ERROR;
        }
    }

    /* ngx_base64_decoded_length is ((n+3)/4)*3; guard against size_t wrap. */
    if (in->len > (size_t) NGX_MAX_SIZE_T_VALUE / 3 * 4 - 3) {
        return NGX_ERROR;
    }

    dst.len = ngx_base64_decoded_length(in->len);
    dst.data = ngx_pnalloc(pool, dst.len);
    if (dst.data == NULL) {
        return NGX_ERROR;
    }

    if (ngx_decode_base64url(&dst, in) != NGX_OK) {
        return NGX_ERROR;
    }

    *out = dst;
    return NGX_OK;
}


/*
 * Extract the affine public coordinates X and Y as fixed-width big-endian
 * buffers of exactly c->coord_len bytes (left-padded with zeros).
 */
static ngx_int_t
ngx_http_autocert_ec_xy(ngx_pool_t *pool,
    const ngx_http_autocert_curve_t *c, EVP_PKEY *pkey,
    ngx_str_t *x, ngx_str_t *y)
{
    BIGNUM   *bx = NULL, *by = NULL;
    u_char   *xb, *yb;
    ngx_int_t rc = NGX_ERROR;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bx) != 1
        || EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &by) != 1)
    {
        goto done;
    }

    xb = ngx_pnalloc(pool, c->coord_len);
    yb = ngx_pnalloc(pool, c->coord_len);
    if (xb == NULL || yb == NULL) {
        goto done;
    }

    /* BN_bn2binpad emits a fixed-width, left-zero-padded big-endian buffer. */
    if (BN_bn2binpad(bx, xb, c->coord_len) != (int) c->coord_len
        || BN_bn2binpad(by, yb, c->coord_len) != (int) c->coord_len)
    {
        goto done;
    }

    x->data = xb; x->len = c->coord_len;
    y->data = yb; y->len = c->coord_len;
    rc = NGX_OK;

done:
    BN_free(bx);
    BN_free(by);
    return rc;
}


/*
 * Build the canonical public JWK string. RFC 7638 §3.3 requires, for an EC
 * key, exactly the members crv, kty, x, y in lexicographic order with no
 * whitespace — which is what the thumbprint hashes, so we always emit that
 * exact form (it is also a valid JWK for the JWS header).
 */
ngx_int_t
ngx_http_autocert_jwk_public(ngx_pool_t *pool, EVP_PKEY *pkey, ngx_str_t *out)
{
    const ngx_http_autocert_curve_t  *c;
    ngx_str_t   x, y, xb64, yb64;
    u_char     *p;
    size_t      size;

    c = ngx_http_autocert_curve_of(pkey);
    if (c == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, pool->log, 0,
                       "autocert: jwk_public: unsupported/non-EC key");
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "autocert: building public JWK, crv=%s", c->jwk_crv);

    if (ngx_http_autocert_ec_xy(pool, c, pkey, &x, &y) != NGX_OK
        || ngx_http_autocert_base64url_encode(pool, &x, &xb64) != NGX_OK
        || ngx_http_autocert_base64url_encode(pool, &y, &yb64) != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* {"crv":"P-384","kty":"EC","x":"…","y":"…"} */
    size = sizeof("{\"crv\":\"\",\"kty\":\"EC\",\"x\":\"\",\"y\":\"\"}") - 1
           + ngx_strlen(c->jwk_crv) + xb64.len + yb64.len;

    p = ngx_pnalloc(pool, size);
    if (p == NULL) {
        return NGX_ERROR;
    }

    out->data = p;
    p = ngx_cpymem(p, "{\"crv\":\"", sizeof("{\"crv\":\"") - 1);
    p = ngx_cpymem(p, c->jwk_crv, ngx_strlen(c->jwk_crv));
    p = ngx_cpymem(p, "\",\"kty\":\"EC\",\"x\":\"",
                   sizeof("\",\"kty\":\"EC\",\"x\":\"") - 1);
    p = ngx_cpymem(p, xb64.data, xb64.len);
    p = ngx_cpymem(p, "\",\"y\":\"", sizeof("\",\"y\":\"") - 1);
    p = ngx_cpymem(p, yb64.data, yb64.len);
    *p++ = '"';
    *p++ = '}';

    out->len = p - out->data;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "autocert: public JWK built, %uz bytes", out->len);
    return NGX_OK;
}


ngx_int_t
ngx_http_autocert_jwk_thumbprint(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *out)
{
    ngx_str_t  jwk, digest;
    u_char     md[SHA256_DIGEST_LENGTH];

    if (ngx_http_autocert_jwk_public(pool, pkey, &jwk) != NGX_OK) {
        return NGX_ERROR;
    }

    if (SHA256(jwk.data, jwk.len, md) == NULL) {
        return NGX_ERROR;
    }

    digest.data = md;
    digest.len = SHA256_DIGEST_LENGTH;

    return ngx_http_autocert_base64url_encode(pool, &digest, out);
}


const char *
ngx_http_autocert_jws_alg(EVP_PKEY *pkey)
{
    const ngx_http_autocert_curve_t  *c;

    c = ngx_http_autocert_curve_of(pkey);
    return c ? c->jws_alg : NULL;
}


/*
 * OpenSSL signs ECDSA as a DER SEQUENCE{r,s}; JOSE wants the raw fixed-width
 * R||S concatenation (RFC 7518 §3.4). Convert in place into `out` (2*coord_len
 * bytes, each integer left-zero-padded).
 */
static ngx_int_t
ngx_http_autocert_der_to_jose(const ngx_http_autocert_curve_t *c,
    const u_char *der, size_t derlen, u_char *out)
{
    const unsigned char  *p = der;
    ECDSA_SIG            *sig;
    const BIGNUM         *r, *s;
    ngx_int_t             rc = NGX_ERROR;

    sig = d2i_ECDSA_SIG(NULL, &p, derlen);
    if (sig == NULL) {
        return NGX_ERROR;
    }

    ECDSA_SIG_get0(sig, &r, &s);

    if (BN_bn2binpad(r, out, c->coord_len) != (int) c->coord_len
        || BN_bn2binpad(s, out + c->coord_len, c->coord_len)
           != (int) c->coord_len)
    {
        goto done;
    }

    rc = NGX_OK;

done:
    ECDSA_SIG_free(sig);
    return rc;
}


ngx_int_t
ngx_http_autocert_jws_sign(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *protected_json, ngx_str_t *payload, ngx_str_t *out)
{
    const ngx_http_autocert_curve_t  *c;
    EVP_MD_CTX  *mdctx = NULL;
    ngx_str_t    prot_b64, pay_b64, sig_b64, signing_input, raw_sig;
    u_char      *der = NULL, *p, *jose;
    size_t       derlen, max_der;
    ngx_int_t    rc = NGX_ERROR;

    c = ngx_http_autocert_curve_of(pkey);
    if (c == NULL) {
        return NGX_ERROR;
    }

    if (ngx_http_autocert_base64url_encode(pool, protected_json, &prot_b64)
            != NGX_OK
        || ngx_http_autocert_base64url_encode(pool, payload, &pay_b64)
            != NGX_OK)
    {
        return NGX_ERROR;
    }

    /* JWS signing input = BASE64URL(protected) || '.' || BASE64URL(payload) */
    if (prot_b64.len > NGX_MAX_SIZE_T_VALUE - 1 - pay_b64.len) {
        return NGX_ERROR;
    }
    signing_input.len = prot_b64.len + 1 + pay_b64.len;
    signing_input.data = ngx_pnalloc(pool, signing_input.len);
    if (signing_input.data == NULL) {
        return NGX_ERROR;
    }
    p = ngx_cpymem(signing_input.data, prot_b64.data, prot_b64.len);
    *p++ = '.';
    ngx_memcpy(p, pay_b64.data, pay_b64.len);

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        return NGX_ERROR;
    }

    /* Worst-case DER size for two coord_len ints: tag/len overhead per int. */
    max_der = 2 * (c->coord_len + 1) + 8;
    der = ngx_pnalloc(pool, max_der);
    if (der == NULL) {
        goto done;
    }

    if (EVP_DigestSignInit(mdctx, NULL, c->md(), NULL, pkey) != 1) {
        goto done;
    }

    derlen = max_der;
    if (EVP_DigestSign(mdctx, der, &derlen,
                       signing_input.data, signing_input.len) != 1)
    {
        goto done;
    }

    jose = ngx_pnalloc(pool, 2 * c->coord_len);
    if (jose == NULL) {
        goto done;
    }

    if (ngx_http_autocert_der_to_jose(c, der, derlen, jose) != NGX_OK) {
        goto done;
    }

    raw_sig.data = jose;
    raw_sig.len = 2 * c->coord_len;

    if (ngx_http_autocert_base64url_encode(pool, &raw_sig, &sig_b64)
        != NGX_OK)
    {
        goto done;
    }

    /* {"protected":"…","payload":"…","signature":"…"} */
    {
        size_t  fixed = sizeof("{\"protected\":\"\",\"payload\":\"\","
                               "\"signature\":\"\"}") - 1;

        /* prot_b64.len + pay_b64.len is already bounded (signing_input guard);
         * fold in the fixed overhead and the signature length with wrap checks. */
        if (sig_b64.len > NGX_MAX_SIZE_T_VALUE - fixed
            || prot_b64.len + pay_b64.len
               > NGX_MAX_SIZE_T_VALUE - fixed - sig_b64.len)
        {
            goto done;
        }
        out->len = fixed + prot_b64.len + pay_b64.len + sig_b64.len;
    }
    out->data = ngx_pnalloc(pool, out->len);
    if (out->data == NULL) {
        goto done;
    }

    p = out->data;
    p = ngx_cpymem(p, "{\"protected\":\"", sizeof("{\"protected\":\"") - 1);
    p = ngx_cpymem(p, prot_b64.data, prot_b64.len);
    p = ngx_cpymem(p, "\",\"payload\":\"", sizeof("\",\"payload\":\"") - 1);
    p = ngx_cpymem(p, pay_b64.data, pay_b64.len);
    p = ngx_cpymem(p, "\",\"signature\":\"",
                   sizeof("\",\"signature\":\"") - 1);
    p = ngx_cpymem(p, sig_b64.data, sig_b64.len);
    *p++ = '"';
    *p++ = '}';
    out->len = p - out->data;

    rc = NGX_OK;

done:
    EVP_MD_CTX_free(mdctx);
    return rc;
}


/*
 * Build a PKCS#10 CSR for `domain`, signed with `pkey` (the certificate key),
 * and emit its DER encoding into *out (pool-allocated).
 *
 * The subject is left EMPTY — ACME ignores the CSR subject and takes the names
 * exclusively from the subjectAltName extension (RFC 8555 §7.4). Per RFC 5280
 * §4.2.1.6 a SAN with an empty subject MUST be marked critical, so it is.
 * Signed with the curve-matched digest (SHA-256 for P-256, SHA-384 for P-384).
 */
ngx_int_t
ngx_http_autocert_csr_der(ngx_pool_t *pool, EVP_PKEY *pkey, ngx_str_t *domain,
    ngx_str_t *out)
{
    ngx_int_t                          rc = NGX_ERROR;
    int                                der_len;
    u_char                            *der = NULL;
    X509_REQ                          *req = NULL;
    STACK_OF(X509_EXTENSION)          *exts = NULL;
    X509_EXTENSION                    *san = NULL;
    GENERAL_NAME                      *gn = NULL;
    GENERAL_NAMES                     *gns = NULL;
    ASN1_IA5STRING                    *ia5 = NULL;
    const ngx_http_autocert_curve_t   *cv;

    cv = ngx_http_autocert_curve_of(pkey);
    if (cv == NULL || domain->len == 0) {
        return NGX_ERROR;
    }

    req = X509_REQ_new();
    if (req == NULL) {
        return NGX_ERROR;
    }
    if (X509_REQ_set_version(req, 0) != 1            /* v1 */
        || X509_REQ_set_pubkey(req, pkey) != 1)
    {
        goto done;
    }

    /* subjectAltName = DNS:<domain>, built by hand to bound the name length
     * (no NUL-terminated input assumed). */
    gns = GENERAL_NAMES_new();
    gn = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    if (gns == NULL || gn == NULL || ia5 == NULL) {
        goto done;
    }
    if (domain->len > INT_MAX
        || ASN1_STRING_set(ia5, domain->data, (int) domain->len) != 1)
    {
        goto done;
    }
    GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
    ia5 = NULL;                                      /* owned by gn now */
    if (sk_GENERAL_NAME_push(gns, gn) <= 0) {
        goto done;
    }
    gn = NULL;                                       /* owned by gns now */

    san = X509V3_EXT_i2d(NID_subject_alt_name, 1 /* critical */, gns);
    if (san == NULL) {
        goto done;
    }

    exts = sk_X509_EXTENSION_new_null();
    if (exts == NULL || sk_X509_EXTENSION_push(exts, san) <= 0) {
        goto done;
    }
    san = NULL;                                      /* owned by exts now */
    if (X509_REQ_add_extensions(req, exts) != 1) {
        goto done;
    }

    if (X509_REQ_sign(req, pkey, cv->md()) == 0) {
        goto done;
    }

    der_len = i2d_X509_REQ(req, &der);
    if (der_len <= 0 || der == NULL) {
        goto done;
    }

    out->data = ngx_pnalloc(pool, der_len);
    if (out->data == NULL) {
        goto done;
    }
    ngx_memcpy(out->data, der, der_len);
    out->len = der_len;
    rc = NGX_OK;

done:
    if (der != NULL) {
        OPENSSL_free(der);
    }
    if (ia5 != NULL) {
        ASN1_STRING_free(ia5);
    }
    if (gn != NULL) {
        GENERAL_NAME_free(gn);
    }
    if (gns != NULL) {
        GENERAL_NAMES_free(gns);
    }
    if (san != NULL) {
        X509_EXTENSION_free(san);
    }
    if (exts != NULL) {
        sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    }
    if (req != NULL) {
        X509_REQ_free(req);
    }
    return rc;
}


/*
 * M7 bootstrap: self-signed dummy cert. See the header. The digest is chosen
 * from the key's curve (SHA-256 for P-256, SHA-384 for P-384) so the signature
 * matches the key strength; any EC key works.
 */
X509 *
ngx_http_autocert_dummy_cert(EVP_PKEY *pkey)
{
    X509          *x = NULL;
    X509_NAME     *name = NULL;
    ASN1_INTEGER  *serial = NULL;
    const EVP_MD  *md;

    if (pkey == NULL) {
        return NULL;
    }

    x = X509_new();
    if (x == NULL) {
        return NULL;
    }

    if (X509_set_version(x, 2) != 1) {                /* X.509 v3 */
        goto failed;
    }

    serial = ASN1_INTEGER_new();
    if (serial == NULL || ASN1_INTEGER_set(serial, 1) != 1
        || X509_set_serialNumber(x, serial) != 1)
    {
        goto failed;
    }

    if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 24L * 60 * 60) == NULL)
    {
        goto failed;
    }

    if (X509_set_pubkey(x, pkey) != 1) {
        goto failed;
    }

    name = X509_get_subject_name(x);                  /* internal ptr */
    if (name == NULL
        || X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      (const unsigned char *) "localhost",
                                      -1, -1, 0) != 1
        || X509_set_issuer_name(x, name) != 1)        /* self-signed */
    {
        goto failed;
    }

    /*
     * Curve-matched digest, picked from the key strength via the portable
     * EVP_PKEY_bits API (P-384 -> 384) — avoids the OpenSSL 3 deprecated
     * EC_KEY accessors (CI builds -Werror).
     */
    md = (EVP_PKEY_bits(pkey) > 256) ? EVP_sha384() : EVP_sha256();

    if (X509_sign(x, pkey, md) == 0) {
        goto failed;
    }

    ASN1_INTEGER_free(serial);
    return x;

failed:

    if (serial != NULL) {
        ASN1_INTEGER_free(serial);
    }
    X509_free(x);
    return NULL;
}


X509 *
ngx_http_autocert_acme_tls_cert(EVP_PKEY *pkey, ngx_str_t *domain,
    ngx_str_t *keyauth)
{
    X509               *x = NULL;
    X509_NAME          *name;
    ASN1_INTEGER       *serial = NULL;
    GENERAL_NAMES      *gns = NULL;
    GENERAL_NAME       *gn = NULL;
    ASN1_IA5STRING     *ia5 = NULL;
    X509_EXTENSION     *san = NULL;
    X509_EXTENSION     *acmeid = NULL;
    ASN1_OBJECT        *obj = NULL;
    ASN1_OCTET_STRING  *inner = NULL;
    ASN1_OCTET_STRING  *value = NULL;
    unsigned char       digest[SHA256_DIGEST_LENGTH];
    unsigned char      *der = NULL;
    int                 der_len;
    const EVP_MD       *md;

    if (pkey == NULL || domain == NULL || domain->len == 0
        || keyauth == NULL || keyauth->len == 0)
    {
        return NULL;
    }

    /* The acmeIdentifier value is SHA-256 over the key authorization. */
    if (SHA256(keyauth->data, keyauth->len, digest) == NULL) {
        return NULL;
    }

    x = X509_new();
    if (x == NULL) {
        return NULL;
    }
    if (X509_set_version(x, 2) != 1) {                /* X.509 v3 (extensions) */
        goto failed;
    }

    serial = ASN1_INTEGER_new();
    if (serial == NULL || ASN1_INTEGER_set(serial, 1) != 1
        || X509_set_serialNumber(x, serial) != 1)
    {
        goto failed;
    }

    if (X509_gmtime_adj(X509_getm_notBefore(x), 0) == NULL
        || X509_gmtime_adj(X509_getm_notAfter(x), 24L * 60 * 60) == NULL)
    {
        goto failed;
    }
    if (X509_set_pubkey(x, pkey) != 1) {
        goto failed;
    }

    /* Empty subject; self-signed (issuer == subject). The identity lives in the
     * subjectAltName, per RFC 8737. */
    name = X509_get_subject_name(x);                  /* internal ptr */
    if (name == NULL || X509_set_issuer_name(x, name) != 1) {
        goto failed;
    }

    /* subjectAltName = DNS:<domain>, length-bounded (no NUL assumed). */
    gns = GENERAL_NAMES_new();
    gn = GENERAL_NAME_new();
    ia5 = ASN1_IA5STRING_new();
    if (gns == NULL || gn == NULL || ia5 == NULL) {
        goto failed;
    }
    if (domain->len > INT_MAX
        || ASN1_STRING_set(ia5, domain->data, (int) domain->len) != 1)
    {
        goto failed;
    }
    GENERAL_NAME_set0_value(gn, GEN_DNS, ia5);
    ia5 = NULL;                                       /* owned by gn now */
    if (sk_GENERAL_NAME_push(gns, gn) <= 0) {
        goto failed;
    }
    gn = NULL;                                        /* owned by gns now */
    /* Subject is empty, so the SAN MUST be critical (RFC 5280 §4.2.1.6). */
    san = X509V3_EXT_i2d(NID_subject_alt_name, 1 /* critical */, gns);
    if (san == NULL || X509_add_ext(x, san, -1) != 1) {  /* add_ext dups */
        goto failed;
    }

    /* CRITICAL id-pe-acmeIdentifier: extnValue is the DER of an OCTET STRING
     * wrapping the 32-byte digest. */
    inner = ASN1_OCTET_STRING_new();
    if (inner == NULL
        || ASN1_OCTET_STRING_set(inner, digest, (int) sizeof(digest)) != 1)
    {
        goto failed;
    }
    der_len = i2d_ASN1_OCTET_STRING(inner, &der);
    if (der_len <= 0 || der == NULL) {
        goto failed;
    }
    value = ASN1_OCTET_STRING_new();
    if (value == NULL || ASN1_OCTET_STRING_set(value, der, der_len) != 1) {
        goto failed;
    }
    obj = OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1 /* numeric OID only */);
    if (obj == NULL) {
        goto failed;
    }
    acmeid = X509_EXTENSION_create_by_OBJ(NULL, obj, 1 /* critical */, value);
    if (acmeid == NULL || X509_add_ext(x, acmeid, -1) != 1) {
        goto failed;
    }

    md = (EVP_PKEY_bits(pkey) > 256) ? EVP_sha384() : EVP_sha256();
    if (X509_sign(x, pkey, md) == 0) {
        goto failed;
    }

    OPENSSL_free(der);
    ASN1_OCTET_STRING_free(inner);
    ASN1_OCTET_STRING_free(value);
    ASN1_OBJECT_free(obj);
    X509_EXTENSION_free(san);
    X509_EXTENSION_free(acmeid);
    GENERAL_NAMES_free(gns);
    ASN1_INTEGER_free(serial);
    return x;

failed:

    if (der != NULL)    { OPENSSL_free(der); }
    if (inner != NULL)  { ASN1_OCTET_STRING_free(inner); }
    if (value != NULL)  { ASN1_OCTET_STRING_free(value); }
    if (obj != NULL)    { ASN1_OBJECT_free(obj); }
    if (san != NULL)    { X509_EXTENSION_free(san); }
    if (acmeid != NULL) { X509_EXTENSION_free(acmeid); }
    if (ia5 != NULL)    { ASN1_STRING_free(ia5); }
    if (gn != NULL)     { GENERAL_NAME_free(gn); }
    if (gns != NULL)    { GENERAL_NAMES_free(gns); }
    if (serial != NULL) { ASN1_INTEGER_free(serial); }
    X509_free(x);
    return NULL;
}


/*
 * Convert a UTC `struct tm` to a Unix time_t without relying on the non-POSIX
 * timegm(3) or the process timezone. Days-since-epoch via the civil-from-days
 * algorithm; only the fields ASN1_TIME_to_tm populates are used. Returns
 * (time_t) -1 on an out-of-range year.
 */
static time_t
ngx_autocert_timegm(const struct tm *tm)
{
    int64_t  y = tm->tm_year + 1900;
    int64_t  m = tm->tm_mon + 1;       /* 1..12 */
    int64_t  d = tm->tm_mday;          /* 1..31 */
    int64_t  era, yoe, doy, doe, days;

    if (y < 1970 || y > 9999) {
        return (time_t) -1;
    }

    /* Howard Hinnant's days_from_civil: days since 1970-01-01. */
    y -= (m <= 2);
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;                                  /* 0..399 */
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1; /* 0..365 */
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;          /* 0..146096 */
    days = era * 146097 + doe - 719468;

    return (time_t) (days * 86400
                     + tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec);
}


/*
 * Read the leaf cert's notAfter from the PEM fullchain at `path`. See the
 * header for the contract. ENOENT/ENOTDIR => NGX_DECLINED (no cert yet);
 * other failures => NGX_ERROR.
 */
ngx_int_t
ngx_http_autocert_cert_not_after(const char *path, time_t *out)
{
    int         fd;
    BIO        *bio;
    X509       *leaf;
    struct tm   tm;
    time_t      t;
    ngx_int_t   rc;

    /* O_NOFOLLOW: never traverse a symlink at the final path component, and
     * capture errno from open() (BIO_new_file's errno is unreliable). */
    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd == -1) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return NGX_DECLINED;            /* no cert stored yet */
        }
        return NGX_ERROR;                   /* ELOOP (symlink), EACCES, ... */
    }

    bio = BIO_new_fd(fd, BIO_CLOSE);        /* BIO owns + closes fd */
    if (bio == NULL) {
        (void) close(fd);
        return NGX_ERROR;
    }

    leaf = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (leaf == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(&tm, sizeof(struct tm));

    rc = NGX_ERROR;

    /* ASN1_TIME_to_tm fills a UTC struct tm. */
    if (ASN1_TIME_to_tm(X509_get0_notAfter(leaf), &tm) == 1) {
        t = ngx_autocert_timegm(&tm);
        if (t != (time_t) -1) {
            *out = t;
            rc = NGX_OK;
        }
    }

    X509_free(leaf);
    return rc;
}
