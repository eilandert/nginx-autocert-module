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
#include <openssl/x509.h>


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
/*
 * PEM-encode an X509 certificate into *out (pool-allocated). Used to persist a
 * locally built self-signed cert (e.g. the tls-alpn-01 challenge cert, M10b)
 * into the shared store. Returns NGX_OK / NGX_ERROR.
 */
ngx_int_t ngx_http_autocert_cert_to_pem(ngx_pool_t *pool, X509 *cert,
    ngx_str_t *out);

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
 * HMAC-SHA256 over `msg` with raw key `key`, emitting the 32-byte MAC into
 * *out (pool-allocated). Used to build the EAB (External Account Binding) outer
 * JWS signature (RFC 8555 §7.3.4 / RFC 7515 §3.5, "HS256"). Returns NGX_OK /
 * NGX_ERROR. No nginx HTTP dependency — unit-testable against RFC 4231 vectors.
 */
ngx_int_t ngx_http_autocert_hmac_sha256(ngx_pool_t *pool, ngx_str_t *key,
    ngx_str_t *msg, ngx_str_t *out);


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


/*
 * Generate a throwaway self-signed certificate for `pkey` (M7 bootstrap): the
 * SSL_CTX of an `autocert on;` server needs *a* valid cert/key pair so the
 * listener comes up before the real cert is issued; cert_cb swaps the real
 * per-SNI cert in at handshake. Subject/issuer CN = "localhost", serial 1,
 * notBefore now, notAfter +1 day (long enough for the bootstrap window; the
 * dummy never reaches a client — cert_cb replaces it). Returns an X509* (caller
 * frees with X509_free) or NULL. No nginx/pool dependency.
 */
X509 *ngx_http_autocert_dummy_cert(EVP_PKEY *pkey);


/*
 * Build the RFC 8737 tls-alpn-01 challenge certificate (M10): a self-signed
 * cert for `domain` carrying
 *   - a subjectAltName dNSName == domain, and
 *   - a CRITICAL id-pe-acmeIdentifier extension (OID 1.3.6.1.5.5.7.1.31) whose
 *     value is the DER encoding of an OCTET STRING containing SHA-256(keyauth).
 * `pkey` is the (throwaway) cert key. `keyauth` is the ACME key authorization
 * (token "." base64url(JWK thumbprint)). The CA validates domain control by
 * connecting with ALPN "acme-tls/1" + SNI=domain and checking this extension —
 * no port 80 needed. Returns a new X509* (free with X509_free) or NULL. No
 * nginx/pool dependency.
 */
X509 *ngx_http_autocert_acme_tls_cert(EVP_PKEY *pkey, ngx_str_t *domain,
    ngx_str_t *keyauth);


/*
 * Read the leaf certificate's notAfter from a PEM fullchain file at `path`
 * (NUL-terminated C string) and convert it to a Unix `time_t` in *out. The
 * leaf is the FIRST certificate in the file (per the store layout). Returns
 * NGX_OK on success; NGX_DECLINED if the file is absent (ENOENT/ENOTDIR);
 * NGX_ERROR on any other open/parse failure. Used by the renewal scheduler
 * (M8) to decide whether a stored cert is inside its renew window. No nginx
 * pool dependency.
 */
ngx_int_t ngx_http_autocert_cert_not_after(const char *path, time_t *out);


#endif /* _NGX_HTTP_AUTOCERT_CRYPTO_H_INCLUDED_ */
