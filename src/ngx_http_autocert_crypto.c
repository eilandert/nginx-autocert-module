/*
 * ngx_http_autocert_crypto — JOSE/ACME crypto primitives (M3).
 * See ngx_http_autocert_crypto.h for the contract.
 */

#include "ngx_http_autocert_crypto.h"

#include <limits.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
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

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
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
#else
    {
        const EC_KEY    *ec;
        const EC_GROUP  *group;

        ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (ec != NULL) {
            group = EC_KEY_get0_group(ec);
            if (group != NULL) {
                nid = EC_GROUP_get_curve_name(group);
            }
        }
    }
#endif

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
 * buffers of exactly c->coord_len bytes (left-padded with zeros). Both 3.0+
 * (param API) and 1.1.1 (EC_POINT) paths land on the same BIGNUM pair.
 */
static ngx_int_t
ngx_http_autocert_ec_xy(ngx_pool_t *pool,
    const ngx_http_autocert_curve_t *c, EVP_PKEY *pkey,
    ngx_str_t *x, ngx_str_t *y)
{
    BIGNUM   *bx = NULL, *by = NULL;
    u_char   *xb, *yb;
    ngx_int_t rc = NGX_ERROR;

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bx) != 1
        || EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &by) != 1)
    {
        goto done;
    }
#else
    {
        const EC_KEY    *ec;
        const EC_GROUP  *group;
        const EC_POINT  *pub;

        ec = EVP_PKEY_get0_EC_KEY(pkey);
        if (ec == NULL) {
            goto done;
        }
        group = EC_KEY_get0_group(ec);
        pub = EC_KEY_get0_public_key(ec);
        if (group == NULL || pub == NULL) {
            goto done;
        }

        bx = BN_new();
        by = BN_new();
        if (bx == NULL || by == NULL) {
            goto done;
        }

        if (EC_POINT_get_affine_coordinates(group, pub, bx, by, NULL) != 1) {
            goto done;
        }
    }
#endif

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
        return NGX_ERROR;
    }

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
