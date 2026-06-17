/*
 * Unit tests for ngx_http_autocert_crypto (M3).
 *
 * Standalone harness: links the crypto translation unit against an nginx build
 * tree (for ngx_pool / ngx_str / ngx_base64) plus OpenSSL. Verifies:
 *   - base64url round-trip + known vectors (RFC 4648 / JOSE no-padding)
 *   - fixed P-256 key → canonical JWK and RFC 7638 thumbprint (locked vector,
 *     cross-checked against the openssl CLI)
 *   - JWK member order is the RFC 7638 canonical {crv,kty,x,y}
 *   - generated keys (P-256 and P-384) produce a JWS whose ECDSA R||S
 *     signature verifies against the public key and matches the curve's alg
 *
 * Exit 0 = all pass; non-zero on first failure (prints which).
 *
 * Driven from the CI build-test workflow once an nginx tree is present.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "../src/ngx_http_autocert_crypto.h"

#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>


/* Locked P-256 vector (see test/vec_p256_p8.pem; derived via openssl CLI). */
static const char *VEC_P256_PEM =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgCiiqnUnKUr9CM7ky\n"
    "tL3XPlXXrm5/yX9Ra0S+A+61kQChRANCAATOPC4hvOpIersqqDf4KBwAwcMDJdVY\n"
    "8B7ypOJn7YXtX0qfHOo+M8nVgehsMNagM9ucpfcsFZvKLnQSuEzcWxu4\n"
    "-----END PRIVATE KEY-----\n";

static const char *VEC_P256_JWK =
    "{\"crv\":\"P-256\",\"kty\":\"EC\","
    "\"x\":\"zjwuIbzqSHq7Kqg3-CgcAMHDAyXVWPAe8qTiZ-2F7V8\","
    "\"y\":\"Sp8c6j4zydWB6Gww1qAz25yl9ywVm8oudBK4TNxbG7g\"}";

static const char *VEC_P256_THUMB =
    "gnTD3ejYaoM85Ny1R7N27cQZUxVlGCgTreiBm94DP6Y";


static int failures;
static ngx_pool_t *pool;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)

static int
streq(ngx_str_t *s, const char *lit)
{
    return s->len == ngx_strlen(lit)
           && ngx_strncmp(s->data, lit, s->len) == 0;
}

static ngx_str_t
S(const char *lit)
{
    ngx_str_t s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return s;
}


static void
test_base64url(void)
{
    ngx_str_t  in, enc, dec;

    /* JOSE vectors: no padding, '-'/'_' alphabet. */
    in = S("");        ngx_http_autocert_base64url_encode(pool, &in, &enc);
    CHECK(streq(&enc, ""), "b64url(\"\") == \"\"");

    in = S("f");       ngx_http_autocert_base64url_encode(pool, &in, &enc);
    CHECK(streq(&enc, "Zg"), "b64url(\"f\") == \"Zg\" (no padding)");

    in = S("foobar");  ngx_http_autocert_base64url_encode(pool, &in, &enc);
    CHECK(streq(&enc, "Zm9vYmFy"), "b64url(\"foobar\") == \"Zm9vYmFy\"");

    /* A value that exercises both '+'→'-' and '/'→'_' remapping. */
    in = S("\xfb\xff\xbf"); ngx_http_autocert_base64url_encode(pool, &in, &enc);
    CHECK(streq(&enc, "-_-_"), "b64url(0xfbffbf) == \"-_-_\"");

    /* Round-trip back to the original bytes. */
    ngx_http_autocert_base64url_decode(pool, &enc, &dec);
    CHECK(dec.len == 3
          && (u_char) dec.data[0] == 0xfb
          && (u_char) dec.data[1] == 0xff
          && (u_char) dec.data[2] == 0xbf,
          "b64url decode round-trip");

    /* Strict contract: padding and out-of-alphabet bytes are rejected. */
    in = S("Zg==");
    CHECK(ngx_http_autocert_base64url_decode(pool, &in, &dec) == NGX_ERROR,
          "b64url decode rejects '=' padding");
    in = S("Zm+9");
    CHECK(ngx_http_autocert_base64url_decode(pool, &in, &dec) == NGX_ERROR,
          "b64url decode rejects non-URL-safe '+'");
}


static void
test_jwk_and_thumbprint(void)
{
    ngx_str_t  pem, jwk, thumb;
    EVP_PKEY  *pkey = NULL;

    pem = S(VEC_P256_PEM);
    CHECK(ngx_http_autocert_key_from_pem(&pem, &pkey) == NGX_OK,
          "load fixed P-256 PEM");
    if (pkey == NULL) {
        return;
    }

    CHECK(ngx_http_autocert_jwk_public(pool, pkey, &jwk) == NGX_OK
          && streq(&jwk, VEC_P256_JWK),
          "canonical JWK matches locked vector (crv,kty,x,y order)");

    CHECK(ngx_http_autocert_jwk_thumbprint(pool, pkey, &thumb) == NGX_OK
          && streq(&thumb, VEC_P256_THUMB),
          "RFC 7638 thumbprint matches locked vector");

    ngx_http_autocert_key_free(pkey);
}


/* Decode base64url-in-JSON value for a given key out of a flattened JWS. */
static ngx_int_t
json_b64_field(ngx_str_t *json, const char *key, ngx_str_t *raw_out)
{
    u_char  *p, *q;
    char     pat[32];
    ngx_str_t b64;

    ngx_sprintf((u_char *) pat, "\"%s\":\"%Z", key);
    p = (u_char *) strstr((char *) json->data, pat);
    if (p == NULL) {
        return NGX_ERROR;
    }
    p += ngx_strlen(pat);
    q = (u_char *) strchr((char *) p, '"');
    if (q == NULL) {
        return NGX_ERROR;
    }

    b64.data = p;
    b64.len = q - p;
    return ngx_http_autocert_base64url_decode(pool, &b64, raw_out);
}


static void
test_jws_sign_verify(ngx_uint_t curve, const char *expect_alg)
{
    EVP_PKEY    *pkey;
    ngx_str_t    prot, payload, jws, prot_raw, pay_raw, sig_raw, signing_input;
    const char  *alg;
    EVP_MD_CTX  *mdctx;
    const EVP_MD *md;
    u_char      *der, *p;
    size_t       derlen, half;
    ECDSA_SIG   *sig;
    BIGNUM      *r, *s;
    int          ok;

    pkey = ngx_http_autocert_key_generate(curve);
    CHECK(pkey != NULL, expect_alg);
    if (pkey == NULL) {
        return;
    }

    alg = ngx_http_autocert_jws_alg(pkey);
    CHECK(alg != NULL && strcmp(alg, expect_alg) == 0,
          "jws_alg matches curve");

    prot = S("{\"alg\":\"X\",\"nonce\":\"abc\",\"url\":\"https://ca/acct\"}");
    payload = S("{\"termsOfServiceAgreed\":true}");

    CHECK(ngx_http_autocert_jws_sign(pool, pkey, &prot, &payload, &jws)
              == NGX_OK,
          "jws_sign produces flattened JSON");

    /* protected/payload decode back to the originals. */
    CHECK(json_b64_field(&jws, "protected", &prot_raw) == NGX_OK
          && prot_raw.len == prot.len
          && ngx_memcmp(prot_raw.data, prot.data, prot.len) == 0,
          "jws protected decodes to input");
    CHECK(json_b64_field(&jws, "payload", &pay_raw) == NGX_OK
          && pay_raw.len == payload.len
          && ngx_memcmp(pay_raw.data, payload.data, payload.len) == 0,
          "jws payload decodes to input");

    /* signature is raw R||S of the right width; rebuild DER and verify. */
    CHECK(json_b64_field(&jws, "signature", &sig_raw) == NGX_OK,
          "jws signature decodes");
    half = sig_raw.len / 2;
    CHECK(sig_raw.len % 2 == 0 && (half == 32 || half == 48),
          "signature is fixed-width R||S");

    /* signing input = protected_b64 . payload_b64 (re-derive from jws). */
    {
        u_char *dot;
        u_char *pb, *yb;
        /* pull the two base64url strings straight out of the JWS text */
        pb = (u_char *) strstr((char *) jws.data, "\"protected\":\"")
             + sizeof("\"protected\":\"") - 1;
        dot = (u_char *) strchr((char *) pb, '"');
        yb = (u_char *) strstr((char *) jws.data, "\"payload\":\"")
             + sizeof("\"payload\":\"") - 1;
        signing_input.len = (dot - pb) + 1
            + ((u_char *) strchr((char *) yb, '"') - yb);
        signing_input.data = ngx_pnalloc(pool, signing_input.len);
        p = ngx_cpymem(signing_input.data, pb, dot - pb);
        *p++ = '.';
        ngx_memcpy(p, yb, (u_char *) strchr((char *) yb, '"') - yb);
    }

    sig = ECDSA_SIG_new();
    r = BN_bin2bn(sig_raw.data, half, NULL);
    s = BN_bin2bn(sig_raw.data + half, half, NULL);
    ECDSA_SIG_set0(sig, r, s);
    derlen = i2d_ECDSA_SIG(sig, NULL);
    der = ngx_pnalloc(pool, derlen);
    p = der;
    i2d_ECDSA_SIG(sig, &p);

    md = (half == 32) ? EVP_sha256() : EVP_sha384();
    mdctx = EVP_MD_CTX_new();
    ok = EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) == 1
         && EVP_DigestVerify(mdctx, der, derlen,
                             signing_input.data, signing_input.len) == 1;
    CHECK(ok, "JWS R||S signature verifies against public key");

    EVP_MD_CTX_free(mdctx);
    ECDSA_SIG_free(sig);
    ngx_http_autocert_key_free(pkey);
}


/* Minimal ngx_log stub so the crypto TU links without the full nginx core. */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}


int
main(void)
{
    ngx_pool_t  *p;

    /* ngx_pnalloc/ngx_pcalloc need an initialised time + a pool. */
    ngx_time_init();

    p = ngx_create_pool(16 * 1024, NULL);
    if (p == NULL) {
        fprintf(stderr, "FAIL: pool\n");
        return 2;
    }
    pool = p;

    test_base64url();
    test_jwk_and_thumbprint();
    test_jws_sign_verify(NGX_HTTP_AUTOCERT_CRYPTO_P256, "ES256");
    test_jws_sign_verify(NGX_HTTP_AUTOCERT_CRYPTO_P384, "ES384");

    ngx_destroy_pool(p);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
