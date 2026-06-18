/*
 * ngx_http_autocert_crypto — JOSE/ACME crypto primitives (M3).
 *
 * Self-contained on top of OpenSSL: ECDSA account-key generation (P-256 /
 * P-384), PEM (de)serialisation, base64url, the public JWK and its RFC 7638
 * thumbprint, and ES256/ES384 JWS flattened-JSON signing. No nginx HTTP
 * dependency — only <ngx_core.h> for the pool/str/log types — so it can be
 * unit-tested against known vectors outside a running server.
 *
 * All output buffers are allocated from the ngx_pool_t passed in; callers do
 * not free individually. EVP_PKEY handles are reference-counted OpenSSL
 * objects and MUST be released with ngx_http_autocert_key_free().
 */

#ifndef _NGX_HTTP_AUTOCERT_CRYPTO_H_INCLUDED_
#define _NGX_HTTP_AUTOCERT_CRYPTO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

#include <openssl/evp.h>


/* Curve selector — values match ngx_http_autocert_key_type_e in the module. */
typedef enum {
    NGX_HTTP_AUTOCERT_CRYPTO_P256 = 0,
    NGX_HTTP_AUTOCERT_CRYPTO_P384
} ngx_http_autocert_crypto_curve_e;


/*
 * Generate a fresh ECDSA key on the given curve. Returns an EVP_PKEY* on
 * success (free with ngx_http_autocert_key_free), NULL on failure.
 */
EVP_PKEY *ngx_http_autocert_key_generate(ngx_uint_t curve);

void ngx_http_autocert_key_free(EVP_PKEY *pkey);


/*
 * PEM round-trip for persisting the account key. _to_pem writes an unencrypted
 * PKCS#8 private key into *out (pool-allocated). _from_pem parses one back.
 * Both return NGX_OK / NGX_ERROR; _from_pem stores the key in *out (caller
 * frees with ngx_http_autocert_key_free).
 */
ngx_int_t ngx_http_autocert_key_to_pem(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *out);
ngx_int_t ngx_http_autocert_key_from_pem(ngx_str_t *pem, EVP_PKEY **out);


/*
 * base64url (RFC 4648 §5, no padding). _encode never fails for a valid input;
 * _decode returns NGX_ERROR on a malformed alphabet/length. Both allocate
 * *out from the pool.
 */
ngx_int_t ngx_http_autocert_base64url_encode(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out);
ngx_int_t ngx_http_autocert_base64url_decode(ngx_pool_t *pool, ngx_str_t *in,
    ngx_str_t *out);


/*
 * Build the public JWK JSON for an EC key:
 *   {"crv":"P-256","kty":"EC","x":"…","y":"…"}
 * The member order is the RFC 7638 canonical order (lexicographic keys), so
 * this same string is what the thumbprint hashes — see below. *out is
 * pool-allocated.
 */
ngx_int_t ngx_http_autocert_jwk_public(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *out);


/*
 * RFC 7638 JWK thumbprint: SHA-256 over the canonical JWK, base64url-encoded.
 * This is the value used to form the key authorization in HTTP-01 challenges.
 */
ngx_int_t ngx_http_autocert_jwk_thumbprint(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *out);


/*
 * Produce a flattened-JSON JWS (RFC 7515 §7.2.2) over the given payload,
 * signed with the account key:
 *   {"protected":"…","payload":"…","signature":"…"}
 *
 * `protected_json` is the raw protected-header JSON (caller builds it with the
 * right "alg"/"nonce"/"url"/"jwk"|"kid"); this function base64url-encodes it.
 * `payload` is the raw request body (already JSON, or empty for POST-as-GET).
 * The ECDSA signature is emitted as the fixed-width R||S concatenation that
 * JOSE requires (RFC 7518 §3.4), NOT the DER form OpenSSL signs natively.
 * The JWS "alg" must match the curve (ES256↔P-256, ES384↔P-384); the caller
 * is responsible for putting the matching alg in protected_json.
 *
 * *out is the pool-allocated flattened-JSON string.
 */
ngx_int_t ngx_http_autocert_jws_sign(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *protected_json, ngx_str_t *payload, ngx_str_t *out);


/*
 * Helper exposed for the JWS caller and tests: the JOSE "alg" string
 * ("ES256"/"ES384") for a key's curve, or NULL if unsupported.
 */
const char *ngx_http_autocert_jws_alg(EVP_PKEY *pkey);


/*
 * Build a PKCS#10 certificate-signing request for `domain`, signed with the
 * certificate key `pkey`, and emit its DER bytes into *out (pool-allocated).
 * The subject is empty; the name lives in a critical subjectAltName (RFC 8555
 * §7.4 / RFC 5280 §4.2.1.6). Caller base64url-encodes *out for the ACME
 * finalize request. Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_http_autocert_csr_der(ngx_pool_t *pool, EVP_PKEY *pkey,
    ngx_str_t *domain, ngx_str_t *out);


#endif /* _NGX_HTTP_AUTOCERT_CRYPTO_H_INCLUDED_ */
