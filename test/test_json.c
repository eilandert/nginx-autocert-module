/*
 * Unit tests for ngx_autocert_json (M4c).
 *
 * Standalone harness: links the JSON translation unit against an nginx build
 * tree (for ngx_pool / ngx_str) — no OpenSSL, no running server. Verifies the
 * parser against canned ACME response vectors (directory / account / order /
 * authorization+challenge) plus a battery of escape, edge and malformed-input
 * cases that must be rejected (not crash, not over-read).
 *
 * Exit 0 = all pass; non-zero on first failure (prints which).
 *
 * Driven from the CI build-test workflow once an nginx tree is present.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "../src/ngx_autocert_json.h"

#include <stdio.h>
#include <string.h>


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
    return s->len == strlen(lit)
           && memcmp(s->data, lit, s->len) == 0;
}


/* Parse a NUL-terminated C string literal (length excludes the NUL). */
static ngx_autocert_json_value_t *
parse(const char *lit)
{
    return ngx_autocert_json_parse(pool, (u_char *) lit, strlen(lit));
}


/* Real Let's Encrypt-style directory document. */
static const char *DIRECTORY =
    "{\n"
    "  \"keyChange\": \"https://acme.example/acme/key-change\",\n"
    "  \"newAccount\": \"https://acme.example/acme/new-acct\",\n"
    "  \"newNonce\": \"https://acme.example/acme/new-nonce\",\n"
    "  \"newOrder\": \"https://acme.example/acme/new-order\",\n"
    "  \"revokeCert\": \"https://acme.example/acme/revoke-cert\",\n"
    "  \"meta\": {\n"
    "    \"caaIdentities\": [\"example.org\"],\n"
    "    \"termsOfService\": \"https://acme.example/terms/v1\",\n"
    "    \"website\": \"https://example.org\",\n"
    "    \"externalAccountRequired\": false\n"
    "  }\n"
    "}";

static const char *ACCOUNT =
    "{\"status\":\"valid\","
    "\"contact\":[\"mailto:admin@example.com\"],"
    "\"orders\":\"https://acme.example/acme/acct/1/orders\"}";

static const char *ORDER =
    "{\"status\":\"pending\","
    "\"expires\":\"2026-06-25T00:00:00Z\","
    "\"identifiers\":["
       "{\"type\":\"dns\",\"value\":\"a.example.com\"},"
       "{\"type\":\"dns\",\"value\":\"www.a.example.com\"}],"
    "\"authorizations\":["
       "\"https://acme.example/acme/authz/A\","
       "\"https://acme.example/acme/authz/B\"],"
    "\"finalize\":\"https://acme.example/acme/order/1/finalize\"}";

static const char *AUTHZ =
    "{\"identifier\":{\"type\":\"dns\",\"value\":\"a.example.com\"},"
    "\"status\":\"pending\","
    "\"challenges\":["
       "{\"type\":\"http-01\","
        "\"url\":\"https://acme.example/acme/chall/1\","
        "\"token\":\"DGyRejmCefe7v4NfDGDKfA\"},"
       "{\"type\":\"dns-01\","
        "\"url\":\"https://acme.example/acme/chall/2\","
        "\"token\":\"abc123\"}]}";


static void
test_directory(void)
{
    ngx_autocert_json_value_t  *root, *meta;
    ngx_str_t                   s;

    root = parse(DIRECTORY);
    CHECK(root != NULL && root->type == NGX_AUTOCERT_JSON_OBJECT,
          "directory parses to object");
    if (root == NULL) return;

    CHECK(ngx_autocert_json_object_str(root, "newNonce", &s) == NGX_OK
          && streq(&s, "https://acme.example/acme/new-nonce"),
          "directory newNonce");
    CHECK(ngx_autocert_json_object_str(root, "newAccount", &s) == NGX_OK
          && streq(&s, "https://acme.example/acme/new-acct"),
          "directory newAccount");
    CHECK(ngx_autocert_json_object_str(root, "newOrder", &s) == NGX_OK
          && streq(&s, "https://acme.example/acme/new-order"),
          "directory newOrder");

    /* absent key -> DECLINED, not ERROR */
    CHECK(ngx_autocert_json_object_str(root, "nope", &s) == NGX_DECLINED,
          "absent key returns NGX_DECLINED");

    meta = ngx_autocert_json_object_get(root, "meta");
    CHECK(meta != NULL && meta->type == NGX_AUTOCERT_JSON_OBJECT,
          "directory meta is a nested object");
    CHECK(ngx_autocert_json_object_str(meta, "termsOfService", &s) == NGX_OK
          && streq(&s, "https://acme.example/terms/v1"),
          "meta termsOfService");

    /* nested array of one string */
    {
        ngx_autocert_json_value_t  *caa, *e0;
        caa = ngx_autocert_json_object_get(meta, "caaIdentities");
        CHECK(ngx_autocert_json_array_count(caa) == 1, "caaIdentities len 1");
        e0 = ngx_autocert_json_array_item(caa, 0);
        CHECK(e0 != NULL && e0->type == NGX_AUTOCERT_JSON_STRING
              && streq(&e0->u.string, "example.org"), "caaIdentities[0]");
    }

    /* bool literal */
    {
        ngx_autocert_json_value_t  *ear;
        ear = ngx_autocert_json_object_get(meta, "externalAccountRequired");
        CHECK(ear != NULL && ear->type == NGX_AUTOCERT_JSON_BOOL
              && ear->u.boolean == 0, "externalAccountRequired == false");
    }
}


static void
test_account_order_authz(void)
{
    ngx_autocert_json_value_t  *root, *ids, *id0, *auths, *chs, *ch0;
    ngx_str_t                   s;

    /* account */
    root = parse(ACCOUNT);
    CHECK(ngx_autocert_json_object_str(root, "status", &s) == NGX_OK
          && streq(&s, "valid"), "account status valid");
    CHECK(ngx_autocert_json_object_str(root, "orders", &s) == NGX_OK
          && streq(&s, "https://acme.example/acme/acct/1/orders"),
          "account orders URL");

    /* order */
    root = parse(ORDER);
    CHECK(root != NULL, "order parses");
    CHECK(ngx_autocert_json_object_str(root, "status", &s) == NGX_OK
          && streq(&s, "pending"), "order status pending");
    CHECK(ngx_autocert_json_object_str(root, "finalize", &s) == NGX_OK
          && streq(&s, "https://acme.example/acme/order/1/finalize"),
          "order finalize URL");

    ids = ngx_autocert_json_object_get(root, "identifiers");
    CHECK(ngx_autocert_json_array_count(ids) == 2, "order has 2 identifiers");
    id0 = ngx_autocert_json_array_item(ids, 0);
    CHECK(ngx_autocert_json_object_str(id0, "value", &s) == NGX_OK
          && streq(&s, "a.example.com"), "identifiers[0].value");

    auths = ngx_autocert_json_object_get(root, "authorizations");
    CHECK(ngx_autocert_json_array_count(auths) == 2, "2 authorizations");
    {
        ngx_autocert_json_value_t *a1 = ngx_autocert_json_array_item(auths, 1);
        CHECK(a1 != NULL && a1->type == NGX_AUTOCERT_JSON_STRING
              && streq(&a1->u.string, "https://acme.example/acme/authz/B"),
              "authorizations[1]");
    }
    CHECK(ngx_autocert_json_array_item(auths, 2) == NULL,
          "out-of-range array item is NULL");

    /* authz + challenges */
    root = parse(AUTHZ);
    chs = ngx_autocert_json_object_get(root, "challenges");
    CHECK(ngx_autocert_json_array_count(chs) == 2, "authz has 2 challenges");
    ch0 = ngx_autocert_json_array_item(chs, 0);
    CHECK(ngx_autocert_json_object_str(ch0, "type", &s) == NGX_OK
          && streq(&s, "http-01"), "challenges[0].type http-01");
    CHECK(ngx_autocert_json_object_str(ch0, "token", &s) == NGX_OK
          && streq(&s, "DGyRejmCefe7v4NfDGDKfA"), "challenges[0].token");
}


static void
test_strings_escapes(void)
{
    ngx_autocert_json_value_t  *v;
    ngx_str_t                   s;

    /* every simple escape */
    v = parse("{\"k\":\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\te\"}");
    CHECK(ngx_autocert_json_object_str(v, "k", &s) == NGX_OK
          && s.len == 13
          && memcmp(s.data, "a\"b\\c/d\b\f\n\r\te", 13) == 0,
          "all simple escapes decode");

    /* \uXXXX BMP: U+00E9 (é) -> 2-byte UTF-8 0xC3 0xA9 */
    v = parse("{\"k\":\"caf\\u00e9\"}");
    CHECK(ngx_autocert_json_object_str(v, "k", &s) == NGX_OK
          && s.len == 5
          && memcmp(s.data, "caf\xc3\xa9", 5) == 0,
          "\\u00e9 -> UTF-8 café");

    /* \uXXXX ASCII: U+0041 -> 'A' */
    v = parse("{\"k\":\"\\u0041\"}");
    CHECK(ngx_autocert_json_object_str(v, "k", &s) == NGX_OK
          && streq(&s, "A"), "\\u0041 -> A");

    /* surrogate pair: U+1F600 (emoji) -> 4-byte UTF-8 F0 9F 98 80 */
    v = parse("{\"k\":\"\\ud83d\\ude00\"}");
    CHECK(ngx_autocert_json_object_str(v, "k", &s) == NGX_OK
          && s.len == 4
          && memcmp(s.data, "\xf0\x9f\x98\x80", 4) == 0,
          "surrogate pair -> 4-byte UTF-8");

    /* empty string value */
    v = parse("{\"k\":\"\"}");
    CHECK(ngx_autocert_json_object_str(v, "k", &s) == NGX_OK && s.len == 0,
          "empty string value");

    /* empty object / array */
    v = parse("{}");
    CHECK(v != NULL && v->type == NGX_AUTOCERT_JSON_OBJECT
          && v->u.members == NULL, "empty object {}");
    v = parse("[]");
    CHECK(v != NULL && v->type == NGX_AUTOCERT_JSON_ARRAY
          && ngx_autocert_json_array_count(v) == 0, "empty array []");
}


static void
test_numbers(void)
{
    ngx_autocert_json_value_t  *v, *n;
    ngx_int_t                   i;

    v = parse("{\"a\":0,\"b\":42,\"c\":-7,\"d\":3.14,\"e\":1e3}");
    CHECK(v != NULL, "number object parses");

    n = ngx_autocert_json_object_get(v, "a");
    CHECK(n && n->type == NGX_AUTOCERT_JSON_NUMBER
          && ngx_autocert_json_number_int(n, &i) == NGX_OK && i == 0,
          "int 0");
    n = ngx_autocert_json_object_get(v, "b");
    CHECK(ngx_autocert_json_number_int(n, &i) == NGX_OK && i == 42, "int 42");

    /* negative / fractional / exponent are NUMBERs but not _int */
    n = ngx_autocert_json_object_get(v, "c");
    CHECK(ngx_autocert_json_number_int(n, &i) == NGX_ERROR, "-7 not _int");
    n = ngx_autocert_json_object_get(v, "d");
    CHECK(n->type == NGX_AUTOCERT_JSON_NUMBER
          && ngx_autocert_json_number_int(n, &i) == NGX_ERROR, "3.14 not _int");
    n = ngx_autocert_json_object_get(v, "e");
    CHECK(n->type == NGX_AUTOCERT_JSON_NUMBER, "1e3 is a number");

    /* huge integer overflows _int -> NGX_ERROR, not a wrapped value */
    v = parse("{\"x\":999999999999999999999999}");
    n = ngx_autocert_json_object_get(v, "x");
    CHECK(n && n->type == NGX_AUTOCERT_JSON_NUMBER
          && ngx_autocert_json_number_int(n, &i) == NGX_ERROR,
          "overflow integer rejected by _int");
}


static void
test_type_mismatch(void)
{
    ngx_autocert_json_value_t  *v;
    ngx_str_t                   s;

    /* member present but not a string -> ERROR (distinct from DECLINED) */
    v = parse("{\"k\":123}");
    CHECK(ngx_autocert_json_object_str(v, "k", &s) == NGX_ERROR,
          "non-string member -> NGX_ERROR");

    /* accessors are type-safe on the wrong container type */
    v = parse("[1,2,3]");
    CHECK(ngx_autocert_json_object_get(v, "k") == NULL,
          "object_get on array -> NULL");
    v = parse("\"scalar\"");
    CHECK(ngx_autocert_json_array_count(v) == 0,
          "array_count on string -> 0");
}


static void
test_malformed(void)
{
    /* Each must return NULL (reject), never crash or over-read. */
    static const char *bad[] = {
        "",                       /* empty input */
        "   ",                    /* whitespace only */
        "{",                      /* unterminated object */
        "}",                      /* stray close */
        "[",                      /* unterminated array */
        "[1,]",                   /* trailing comma in array */
        "{\"k\":1,}",             /* trailing comma in object */
        "{\"k\" 1}",              /* missing colon */
        "{k:1}",                  /* unquoted key */
        "{\"k\":}",               /* missing value */
        "{\"a\":1 \"b\":2}",      /* missing comma between members */
        "\"unterminated",         /* unterminated string */
        "\"bad\\xescape\"",       /* invalid escape */
        "\"\\u00g0\"",            /* bad hex in \u */
        "\"\\u00\"",              /* truncated \u: <4 hex digits before quote */
        "\"\\ud83d\"",            /* lone high surrogate */
        "\"\\udc00\"",            /* lone low surrogate */
        "\"\\ud83dx\"",           /* high surrogate not followed by \\u */
        "tru",                    /* truncated literal */
        "truefalse",              /* literal + trailing junk */
        "01",                     /* leading zero */
        "1.",                     /* fraction with no digits */
        "1e",                     /* exponent with no digits */
        "-",                      /* bare minus */
        "nul",                    /* truncated null */
        "{} {}",                  /* two values / trailing junk */
        "\x01",                   /* control byte where a value is expected */
        "{\"a\":\"\x01\"}",       /* raw control char inside a string */
    };
    ngx_uint_t  i;
    char        msg[64];

    for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        ngx_autocert_json_value_t *v = parse(bad[i]);
        snprintf(msg, sizeof(msg), "malformed[%u] rejected", (unsigned) i);
        CHECK(v == NULL, msg);
    }
}


static void
test_no_overread(void)
{
    /*
     * The parser must honour the length, not look for a NUL. Build a buffer
     * with valid JSON followed by garbage that is NOT included in len; parsing
     * the prefix must succeed and stop exactly at len.
     */
    u_char  buf[64];
    ngx_autocert_json_value_t  *v;
    ngx_str_t  s;
    size_t     n;

    memcpy(buf, "{\"k\":\"v\"}GARBAGE", 16);
    n = 9;  /* only the {"k":"v"} part */
    v = ngx_autocert_json_parse(pool, buf, n);
    CHECK(v != NULL && ngx_autocert_json_object_str(v, "k", &s) == NGX_OK
          && streq(&s, "v"), "length-honoured parse ignores trailing garbage");

    /* A truncated buffer (valid prefix but cut mid-token) must be rejected. */
    memcpy(buf, "{\"k\":\"value\"}", 13);
    v = ngx_autocert_json_parse(pool, buf, 8);   /* {"k":"v  -> truncated */
    CHECK(v == NULL, "truncated buffer (cut mid-string) rejected");
}


static void
test_unicode_edge_bounded(void)
{
    /*
     * Surrogate / \u handling at the EXACT length boundary: the buffer ends
     * with no trailing bytes, so a parser that peeks past the high surrogate
     * for the "\u" of a low surrogate (or past a \u for its 4 hex digits)
     * would over-read. These must be rejected (NULL) without touching
     * buf[len]. Built as length-bounded buffers (not C strings) so there is
     * genuinely nothing after the final byte for the parser to read.
     */
    ngx_autocert_json_value_t  *v;

    /* "\ud83d  — a high surrogate as the very last token, buffer ends right
     * after the closing quote: no low surrogate follows, must reject. */
    {
        static const u_char hi[] = { '"', '\\', 'u', 'd', '8', '3', 'd', '"' };
        v = ngx_autocert_json_parse(pool, (u_char *) hi, sizeof(hi));
        CHECK(v == NULL, "bounded: lone high surrogate at buffer end rejected");
    }

    /* High surrogate immediately followed by a backslash but the buffer ends
     * before the 'u' of the would-be low surrogate — must reject, not read on. */
    {
        static const u_char hb[] = {
            '"', '\\', 'u', 'd', '8', '3', 'd', '\\'
        };
        v = ngx_autocert_json_parse(pool, (u_char *) hb, sizeof(hb));
        CHECK(v == NULL, "bounded: high surrogate + bare backslash at end rejected");
    }

    /* A \u escape whose 4 hex digits run past the buffer end: "\u00 then EOF. */
    {
        static const u_char tu[] = { '"', '\\', 'u', '0', '0' };
        v = ngx_autocert_json_parse(pool, (u_char *) tu, sizeof(tu));
        CHECK(v == NULL, "bounded: \\u with <4 hex digits before end rejected");
    }
}


static void
test_depth_limit(void)
{
    /* Nesting beyond the bound must be rejected, not recurse unbounded. */
    u_char   deep[256];
    ngx_uint_t  i, levels = 100;   /* > NGX_AUTOCERT_JSON_MAX_DEPTH (32) */
    ngx_autocert_json_value_t  *v;

    for (i = 0; i < levels; i++) deep[i] = '[';
    for (i = 0; i < levels; i++) deep[levels + i] = ']';

    v = ngx_autocert_json_parse(pool, deep, levels * 2);
    CHECK(v == NULL, "over-deep nesting rejected (depth limit)");

    /* A modest, in-bounds nesting still parses. */
    {
        const char *ok = "[[[[[[[[1]]]]]]]]";  /* 8 deep */
        v = parse(ok);
        CHECK(v != NULL && v->type == NGX_AUTOCERT_JSON_ARRAY,
              "in-bounds nesting parses");
    }
}


int
main(void)
{
    ngx_pool_t  *p;

    ngx_time_init();

    p = ngx_create_pool(64 * 1024, NULL);
    if (p == NULL) {
        fprintf(stderr, "FAIL: pool\n");
        return 2;
    }
    pool = p;

    test_directory();
    test_account_order_authz();
    test_strings_escapes();
    test_numbers();
    test_type_mismatch();
    test_malformed();
    test_no_overread();
    test_unicode_edge_bounded();
    test_depth_limit();

    ngx_destroy_pool(p);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}


/* Minimal ngx_log stub so the TU links without the full nginx core. */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}
