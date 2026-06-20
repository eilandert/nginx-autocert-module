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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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


/* Compare a byte buffer against a lowercase hex string. */
static int
eq_hex(ngx_str_t *got, const char *hex)
{
    size_t  i;

    if (got->len * 2 != ngx_strlen(hex)) {
        return 0;
    }
    for (i = 0; i < got->len; i++) {
        char  b[3];
        snprintf(b, sizeof(b), "%02x", (unsigned) got->data[i]);
        if (b[0] != hex[2 * i] || b[1] != hex[2 * i + 1]) {
            return 0;
        }
    }
    return 1;
}


/* HMAC-SHA256 (the EAB outer-JWS MAC) against RFC 4231 known-answer vectors,
 * plus the EAB-shaped flow: base64url key -> decode -> HMAC. */
static void
test_hmac_sha256(void)
{
    ngx_str_t  key, msg, mac, b64key, rawkey;
    u_char     k1[20];

    /* RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?" */
    key = S("Jefe");
    msg = S("what do ya want for nothing?");
    CHECK(ngx_http_autocert_hmac_sha256(pool, &key, &msg, &mac) == NGX_OK
          && eq_hex(&mac,
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "HMAC-SHA256 RFC 4231 TC2");

    /* RFC 4231 Test Case 1: key = 20 * 0x0b, data="Hi There". */
    ngx_memset(k1, 0x0b, sizeof(k1));
    key.data = k1; key.len = sizeof(k1);
    msg = S("Hi There");
    CHECK(ngx_http_autocert_hmac_sha256(pool, &key, &msg, &mac) == NGX_OK
          && eq_hex(&mac,
              "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
          "HMAC-SHA256 RFC 4231 TC1");

    /* EAB-shaped: the directive carries a base64url key; build_eab decodes it to
     * raw bytes before HMAC. Feed base64url("Jefe")="SmVmZQ" through that path
     * and confirm it reproduces TC2. */
    b64key = S("SmVmZQ");
    CHECK(ngx_http_autocert_base64url_decode(pool, &b64key, &rawkey) == NGX_OK
          && rawkey.len == 4
          && ngx_strncmp(rawkey.data, "Jefe", 4) == 0,
          "base64url EAB key decodes to raw");
    msg = S("what do ya want for nothing?");
    CHECK(ngx_http_autocert_hmac_sha256(pool, &rawkey, &msg, &mac) == NGX_OK
          && eq_hex(&mac,
              "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
          "HMAC over base64url-decoded EAB key matches TC2");
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


/*
 * Generate a key on `curve`, build a CSR for `domain`, then parse the DER back
 * and verify: it is a valid PKCS#10, its signature verifies under its own
 * public key, and its subjectAltName lists exactly the domain.
 */
static void
test_csr(ngx_uint_t curve, const char *domain)
{
    EVP_PKEY                  *pkey;
    ngx_str_t                  dom, der;
    const unsigned char       *dp;
    X509_REQ                  *req;
    EVP_PKEY                  *reqpub;
    GENERAL_NAMES             *gns;
    int                        found, i;

    pkey = ngx_http_autocert_key_generate(curve);
    CHECK(pkey != NULL, "csr: key generate");
    if (pkey == NULL) {
        return;
    }

    dom = S(domain);
    CHECK(ngx_http_autocert_csr_der(pool, pkey, &dom, &der) == NGX_OK
          && der.len > 0,
          "csr: DER produced");
    if (der.len == 0) {
        ngx_http_autocert_key_free(pkey);
        return;
    }

    dp = der.data;
    req = d2i_X509_REQ(NULL, &dp, (long) der.len);
    CHECK(req != NULL, "csr: DER parses as X509_REQ");
    if (req == NULL) {
        ngx_http_autocert_key_free(pkey);
        return;
    }

    reqpub = X509_REQ_get_pubkey(req);
    CHECK(reqpub != NULL && X509_REQ_verify(req, reqpub) == 1,
          "csr: self-signature verifies");

    /* subjectAltName carries exactly the domain as a DNS name. */
    found = 0;
    {
        STACK_OF(X509_EXTENSION)  *exts = X509_REQ_get_extensions(req);

        gns = X509V3_get_d2i(exts, NID_subject_alt_name, NULL, NULL);
        if (exts != NULL) {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
        }
    }
    if (gns != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(gns); i++) {
            GENERAL_NAME  *gn = sk_GENERAL_NAME_value(gns, i);
            if (gn->type == GEN_DNS) {
                ASN1_IA5STRING  *ia5 = gn->d.dNSName;
                if ((size_t) ASN1_STRING_length(ia5) == dom.len
                    && memcmp(ASN1_STRING_get0_data(ia5), dom.data, dom.len)
                       == 0)
                {
                    found = 1;
                }
            }
        }
        GENERAL_NAMES_free(gns);
    }
    CHECK(found, "csr: SAN lists the domain");

    if (reqpub != NULL) {
        EVP_PKEY_free(reqpub);
    }
    X509_REQ_free(req);
    ngx_http_autocert_key_free(pkey);
}


/*
 * Build a tls-alpn-01 challenge cert for `domain` with key authorization
 * `keyauth`, then verify: it self-verifies, lists `domain` in its SAN, and
 * carries a CRITICAL id-pe-acmeIdentifier extension whose value is the DER
 * OCTET STRING of SHA-256(keyauth).
 */
static void
test_acme_tls_cert(ngx_uint_t curve, const char *domain, const char *keyauth)
{
    EVP_PKEY          *pkey;
    ngx_str_t          dom, ka;
    X509              *x;
    GENERAL_NAMES     *gns;
    int                found, i, crit;
    unsigned char      expect[SHA256_DIGEST_LENGTH];
    ASN1_OBJECT       *want;

    pkey = ngx_http_autocert_key_generate(curve);
    CHECK(pkey != NULL, "acme-tls: key generate");
    if (pkey == NULL) {
        return;
    }

    dom = S(domain);
    ka = S(keyauth);
    x = ngx_http_autocert_acme_tls_cert(pkey, &dom, &ka);
    CHECK(x != NULL, "acme-tls: cert built");
    if (x == NULL) {
        ngx_http_autocert_key_free(pkey);
        return;
    }

    CHECK(X509_verify(x, pkey) == 1, "acme-tls: self-signature verifies");

    /* SAN lists exactly the domain. */
    found = 0;
    gns = X509_get_ext_d2i(x, NID_subject_alt_name, NULL, NULL);
    if (gns != NULL) {
        for (i = 0; i < sk_GENERAL_NAME_num(gns); i++) {
            GENERAL_NAME  *gn = sk_GENERAL_NAME_value(gns, i);
            if (gn->type == GEN_DNS) {
                ASN1_IA5STRING  *ia5 = gn->d.dNSName;
                if ((size_t) ASN1_STRING_length(ia5) == dom.len
                    && memcmp(ASN1_STRING_get0_data(ia5), dom.data, dom.len)
                       == 0)
                {
                    found = 1;
                }
            }
        }
        GENERAL_NAMES_free(gns);
    }
    CHECK(found, "acme-tls: SAN lists the domain");

    /* critical id-pe-acmeIdentifier extension == OCTET STRING of SHA256(keyauth) */
    SHA256((const unsigned char *) keyauth, strlen(keyauth), expect);
    want = OBJ_txt2obj("1.3.6.1.5.5.7.1.31", 1);
    found = 0;
    crit = 0;
    for (i = 0; i < X509_get_ext_count(x); i++) {
        X509_EXTENSION     *ext = X509_get_ext(x, i);
        ASN1_OBJECT        *o = X509_EXTENSION_get_object(ext);
        ASN1_OCTET_STRING  *data;
        const unsigned char *dp;
        ASN1_OCTET_STRING  *got;

        if (OBJ_cmp(o, want) != 0) {
            continue;
        }
        crit = X509_EXTENSION_get_critical(ext);
        data = X509_EXTENSION_get_data(ext);
        dp = ASN1_STRING_get0_data(data);
        got = d2i_ASN1_OCTET_STRING(NULL, &dp, ASN1_STRING_length(data));
        if (got != NULL) {
            if (ASN1_STRING_length(got) == (int) sizeof(expect)
                && memcmp(ASN1_STRING_get0_data(got), expect, sizeof(expect))
                   == 0)
            {
                found = 1;
            }
            ASN1_OCTET_STRING_free(got);
        }
    }
    ASN1_OBJECT_free(want);
    CHECK(crit, "acme-tls: acmeIdentifier extension is critical");
    CHECK(found, "acme-tls: acmeIdentifier == SHA256(keyauth)");

    /* The signing digest is curve-matched, not bits-guessed: P-256 must be
     * ecdsa-with-SHA256 and P-384 ecdsa-with-SHA384 (regression for the
     * EVP_PKEY_bits>256 heuristic that would mis-size other curves). */
    {
        int  want_nid = (curve == NGX_HTTP_AUTOCERT_CRYPTO_P256)
                        ? NID_ecdsa_with_SHA256 : NID_ecdsa_with_SHA384;
        int  got_nid  = X509_get_signature_nid(x);
        CHECK(got_nid == want_nid, "acme-tls: signature digest matches curve");
    }

    X509_free(x);
    ngx_http_autocert_key_free(pkey);
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
    test_hmac_sha256();
    test_jwk_and_thumbprint();
    test_jws_sign_verify(NGX_HTTP_AUTOCERT_CRYPTO_P256, "ES256");
    test_jws_sign_verify(NGX_HTTP_AUTOCERT_CRYPTO_P384, "ES384");
    test_csr(NGX_HTTP_AUTOCERT_CRYPTO_P256, "le.example.com");
    test_csr(NGX_HTTP_AUTOCERT_CRYPTO_P384, "example.org");
    test_acme_tls_cert(NGX_HTTP_AUTOCERT_CRYPTO_P256, "le.example.com",
                       "tok-abc.thumbprint-xyz");
    test_acme_tls_cert(NGX_HTTP_AUTOCERT_CRYPTO_P384, "example.org",
                       "another-token.another-thumb");

    ngx_destroy_pool(p);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
