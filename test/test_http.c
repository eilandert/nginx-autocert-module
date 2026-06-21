/*
 * Unit tests for the autocert ACME HTTP-response / URL parser (M4b):
 *   ngx_autocert_acme_parse_url       absolute-https URL splitter
 *   ngx_autocert_acme_parse_response  status-line + header validation
 *
 * DESIGN NOTE — why this is shim+slice, not include+link:
 * ngx_autocert_acme.c is an event-driven TLS client; the parser functions are
 * self-contained byte crunchers, but the rest of the TU references
 * ngx_event_connect / ngx_resolver / ngx_ssl, which would have to be linked
 * (with their transitive deps) just to satisfy the linker for an include-shim
 * build. So we reuse the fuzz infrastructure: fuzz/extract_http.sh slices the
 * parser bodies into fuzz/generated_http.inc, compiled here against
 * fuzz/ngx_http_shim.h — same idiom as fuzz/fuzz_json.c, and the SAME shipped
 * code the fuzzer exercises, with no copy drift. (Reported as a deliberate
 * deviation from the include+link route in the PR.)
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "../fuzz/ngx_http_shim.h"
#include "../fuzz/generated_http.inc"

#include <stdio.h>


static int          failures;
static ngx_pool_t   pool;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static void
req_init(ngx_autocert_acme_request_t *r)
{
    memset(r, 0, sizeof(*r));
    r->pool = &pool;
    r->content_length = -1;
}

static int
streq(ngx_str_t *s, const char *lit)
{
    return s->len == strlen(lit) && memcmp(s->data, lit, s->len) == 0;
}


/* ---- parse_url ---- */

static void
url_ok(const char *url, const char *host, int port, const char *uri,
    ngx_uint_t ipv6)
{
    ngx_autocert_acme_request_t  r;
    char  msg[160];

    req_init(&r);
    r.url.data = (u_char *) url;
    r.url.len = strlen(url);

    snprintf(msg, sizeof(msg), "parse_url ok \"%s\"", url);
    if (ngx_autocert_acme_parse_url(&r) != NGX_OK) {
        CHECK(0, msg);
        return;
    }
    CHECK(streq(&r.host, host) && r.port == port && streq(&r.uri, uri)
          && r.host_is_ipv6 == ipv6, msg);
    ngx_http_fuzz_pool_reset(&pool);
}

static void
url_bad(const char *url)
{
    ngx_autocert_acme_request_t  r;
    char  msg[160];

    req_init(&r);
    r.url.data = (u_char *) url;
    r.url.len = strlen(url);

    snprintf(msg, sizeof(msg), "parse_url reject \"%s\"", url);
    CHECK(ngx_autocert_acme_parse_url(&r) == NGX_ERROR, msg);
    ngx_http_fuzz_pool_reset(&pool);
}

/* parse_url over an explicit (data,len) so we can embed NUL/control bytes. */
static void
url_bad_n(const u_char *data, size_t len, const char *label)
{
    ngx_autocert_acme_request_t  r;

    req_init(&r);
    r.url.data = (u_char *) data;
    r.url.len = len;
    CHECK(ngx_autocert_acme_parse_url(&r) == NGX_ERROR, label);
    ngx_http_fuzz_pool_reset(&pool);
}

static void
test_parse_url(void)
{
    /* scheme / host / port / uri split */
    url_ok("https://acme.example.com/dir", "acme.example.com", 443, "/dir", 0);
    url_ok("https://acme.example.com", "acme.example.com", 443, "/", 0);
    url_ok("https://acme.example.com:8443/x", "acme.example.com", 8443, "/x", 0);
    url_ok("https://acme.example.com:443/", "acme.example.com", 443, "/", 0);
    url_ok("https://[2001:db8::1]/p", "2001:db8::1", 443, "/p", 1);
    url_ok("https://[2001:db8::1]:8443/p", "2001:db8::1", 8443, "/p", 1);
    url_ok("https://h/a/b?c=d&e=f", "h", 443, "/a/b?c=d&e=f", 0);

    /* scheme is case-insensitive */
    url_ok("HTTPS://h/x", "h", 443, "/x", 0);

    /* missing / wrong scheme */
    url_bad("http://acme.example.com/dir");   /* TLS-only: http rejected */
    url_bad("ftp://h/x");
    url_bad("acme.example.com/dir");           /* no scheme */
    url_bad("https://");                       /* empty everything */
    url_bad("https:///path");                  /* empty host */

    /* port edge cases */
    url_bad("https://h:/x");                    /* empty port */
    url_bad("https://h:0/x");                   /* port 0 out of range */
    url_bad("https://h:65536/x");               /* port overflow */
    url_bad("https://h:99999999999/x");         /* huge port */
    url_bad("https://h:8a43/x");                /* non-numeric port */

    /* IPv6 without closing bracket */
    url_bad("https://[2001:db8::1/x");

    /* relative / junk between host and uri */
    url_bad("https://h x/y");                   /* space (control) in host */

    /* control / NUL bytes in host or uri are rejected (url_part_safe) */
    {
        static const u_char nul_host[]  = "https://h\x00x/y";
        static const u_char ctrl_host[] = "https://h\x01x/y";
        static const u_char ctrl_uri[]  = "https://h/a\x01b";
        static const u_char cr_uri[]    = "https://h/a\rb";
        static const u_char lf_uri[]    = "https://h/a\nb";
        url_bad_n(nul_host,  sizeof(nul_host) - 1,  "parse_url reject NUL in host");
        url_bad_n(ctrl_host, sizeof(ctrl_host) - 1, "parse_url reject ctrl in host");
        url_bad_n(ctrl_uri,  sizeof(ctrl_uri) - 1,  "parse_url reject ctrl in uri");
        url_bad_n(cr_uri,    sizeof(cr_uri) - 1,     "parse_url reject CR in uri");
        url_bad_n(lf_uri,    sizeof(lf_uri) - 1,     "parse_url reject LF in uri");
    }
}


/* ---- parse_response: drive it over a fixed response buffer ---- */

static ngx_int_t
parse_resp(const char *resp, size_t len, ngx_autocert_acme_request_t *r)
{
    ngx_buf_t  *b;

    req_init(r);
    b = ngx_pnalloc(&pool, sizeof(ngx_buf_t));
    b->start = ngx_pnalloc(&pool, len ? len : 1);
    memcpy(b->start, resp, len);
    b->pos = b->start;
    b->last = b->start + len;
    b->end = b->last;
    r->recv = b;

    return ngx_autocert_acme_parse_response(r);
}

#define RESP(s)  (s), (sizeof(s) - 1)

static void
test_status_line(void)
{
    ngx_autocert_acme_request_t  r;
    ngx_int_t  rc;

    /* valid 200 with a Content-Length-0 body completes */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_DONE && r.status == 200,
          "status line: HTTP/1.1 200 accepted, status captured");
    ngx_http_fuzz_pool_reset(&pool);

    /* HTTP/1.0 is also accepted */
    rc = parse_resp(RESP("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"),
                    &r);
    CHECK(rc == NGX_DONE && r.status == 404, "status line: HTTP/1.0 accepted");
    ngx_http_fuzz_pool_reset(&pool);

    /* non-HTTP/1.x version rejected */
    rc = parse_resp(RESP("HTTP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: HTTP/2.0 rejected");
    ngx_http_fuzz_pool_reset(&pool);

    rc = parse_resp(RESP("XTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: non-HTTP prefix rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* non-3-digit / non-numeric code rejected */
    rc = parse_resp(RESP("HTTP/1.1 20 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: 2-digit code rejected");
    ngx_http_fuzz_pool_reset(&pool);

    rc = parse_resp(RESP("HTTP/1.1 2zz OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: non-numeric code rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* out-of-range code (< 100 or > 599) rejected */
    rc = parse_resp(RESP("HTTP/1.1 099 X\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: code 099 rejected");
    ngx_http_fuzz_pool_reset(&pool);

    rc = parse_resp(RESP("HTTP/1.1 600 X\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: code 600 rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* missing space after version rejected */
    rc = parse_resp(RESP("HTTP/1.1x200 OK\r\nContent-Length: 0\r\n\r\n"), &r);
    CHECK(rc == NGX_ERROR, "status line: missing space after version rejected");
    ngx_http_fuzz_pool_reset(&pool);
}


static void
test_body_framing(void)
{
    ngx_autocert_acme_request_t  r;
    ngx_int_t  rc;

    /* Content-Length body */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"),
                    &r);
    CHECK(rc == NGX_DONE && r.body_out.len == 5
          && memcmp(r.body_out.data, "hello", 5) == 0,
          "body: Content-Length body captured");
    ngx_http_fuzz_pool_reset(&pool);

    /* partial body -> NGX_AGAIN */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel"), &r);
    CHECK(rc == NGX_AGAIN, "body: short Content-Length body -> AGAIN");
    ngx_http_fuzz_pool_reset(&pool);

    /* chunked body decode */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                         "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"), &r);
    CHECK(rc == NGX_DONE && r.body_out.len == 11
          && memcmp(r.body_out.data, "hello world", 11) == 0,
          "body: chunked decode concatenates chunks");
    ngx_http_fuzz_pool_reset(&pool);

    /* both Content-Length and chunked -> reject */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                         "Transfer-Encoding: chunked\r\n\r\nhello"), &r);
    CHECK(rc == NGX_ERROR, "body: CL + TE rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* unsupported transfer-encoding rejected */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n"
                         "x"), &r);
    CHECK(rc == NGX_ERROR, "body: unsupported Transfer-Encoding rejected");
    ngx_http_fuzz_pool_reset(&pool);

    /* header capture: ngx_autocert_acme_header finds a value */
    rc = parse_resp(RESP("HTTP/1.1 201 Created\r\nLocation: https://acct/1\r\n"
                         "Content-Length: 0\r\n\r\n"), &r);
    {
        ngx_str_t  *loc = ngx_autocert_acme_header(&r, "Location");
        CHECK(rc == NGX_DONE && loc != NULL
              && streq(loc, "https://acct/1"),
              "header: Location captured + case-insensitive lookup");
    }
    ngx_http_fuzz_pool_reset(&pool);

    /* incomplete headers (no CRLFCRLF) -> AGAIN, no over-read */
    rc = parse_resp(RESP("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"), &r);
    CHECK(rc == NGX_AGAIN, "headers: incomplete header block -> AGAIN");
    ngx_http_fuzz_pool_reset(&pool);
}


int
main(void)
{
    pool.nallocs = 0;
    pool.log = NULL;

    test_parse_url();
    test_status_line();
    test_body_framing();

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
