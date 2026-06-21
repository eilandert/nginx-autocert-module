/*
 * Minimal nginx surface for the autocert ACME HTTP-response / URL parser
 * (ngx_autocert_acme_parse_url / parse_response / dechunk / header / memmem /
 * url_part_safe), sliced from ../src/ngx_autocert_acme.c by extract_http.sh
 * into generated_http.inc.
 *
 * Those bodies operate on an ngx_autocert_acme_request_t but touch only a
 * subset of its fields (no event/SSL/resolver machinery), plus the
 * ngx_string/ngx_array helpers below. We reproduce that subset faithfully:
 * field names, types and semantics match src/ngx_autocert_acme.h exactly so
 * the sliced code compiles unchanged. The bodies are NOT copied — only the
 * struct surface they read is shimmed.
 *
 * Used by BOTH the standalone unit test (test/test_http.c, compiled against
 * an nginx tree but the parser surface still routed through this slice) — no,
 * see test_http.c which includes this shim + the .inc directly — and the
 * libFuzzer target fuzz/fuzz_http.c.
 */

#ifndef NGX_AUTOCERT_HTTP_FUZZ_SHIM_H
#define NGX_AUTOCERT_HTTP_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* --- core types (nginx ngx_config.h) --- */
typedef intptr_t    ngx_int_t;
typedef uintptr_t   ngx_uint_t;
typedef unsigned char u_char;
typedef uint16_t    in_port_t;
typedef long        off_t_shim;        /* avoid clashing with system off_t */

#ifndef _OFF_T_DECLARED
/* the slice uses off_t for content_length; the system header provides it. */
#include <sys/types.h>
#endif

typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* --- constants --- */
#define NGX_OK            0
#define NGX_ERROR        -1
#define NGX_AGAIN        -2
#define NGX_DONE         -4
#define NGX_DECLINED     -5

#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_SIZE_T_VALUE   0x7fffffffffffffffLL
#define NGX_MAX_INT_T_VALUE    9223372036854775807LL
#else
#define NGX_MAX_SIZE_T_VALUE   0x7fffffff
#define NGX_MAX_INT_T_VALUE    2147483647
#endif

/* off_t is 64-bit on this target (LFS). Match nginx's ngx_atoof bound. */
#define NGX_MAX_OFF_T_VALUE    0x7fffffffffffffffLL

#define CRLF  "\r\n"

/* --- logging: silent in unit/fuzz harness --- */
#define NGX_LOG_DEBUG_CORE  0
#define NGX_LOG_ERR         0

typedef struct ngx_log_s  ngx_log_t;
struct ngx_log_s { int dummy; };

#define ngx_log_debug1(level, log, err, fmt, a1)              ((void)0)
#define ngx_log_debug2(level, log, err, fmt, a1, a2)          ((void)0)
#define ngx_log_debug3(level, log, err, fmt, a1, a2, a3)      ((void)0)
#define ngx_log_error(level, log, err, ...)                   ((void)0)

/* --- pool shim (malloc-backed, tracked so the harness frees the lot) --- */
#define NGX_HTTP_FUZZ_POOL_MAX_ALLOCS  4096

typedef struct {
    void       *allocs[NGX_HTTP_FUZZ_POOL_MAX_ALLOCS];
    size_t      nallocs;
    ngx_log_t  *log;
} ngx_pool_t;

static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *p;
    if (pool->nallocs >= NGX_HTTP_FUZZ_POOL_MAX_ALLOCS) {
        return NULL;
    }
    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs++] = p;
    return p;
}

static void
ngx_http_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t i;
    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    pool->nallocs = 0;
}

/* --- ngx_array surface used by the header scan --- */
typedef struct {
    void       *elts;
    ngx_uint_t  nelts;
    size_t      size;
    ngx_uint_t  nalloc;
    ngx_pool_t *pool;
} ngx_array_t;

static ngx_array_t *
ngx_array_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_array_t *a = ngx_pnalloc(pool, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }
    a->elts = ngx_pnalloc(pool, n * size);
    if (a->elts == NULL) {
        return NULL;
    }
    a->nelts = 0;
    a->size = size;
    a->nalloc = n;
    a->pool = pool;
    return a;
}

static void *
ngx_array_push(ngx_array_t *a)
{
    void *elt;
    if (a->nelts == a->nalloc) {
        /* grow x2 */
        void   *new_elts;
        size_t  n = 2 * (a->nalloc ? a->nalloc : 1);
        new_elts = ngx_pnalloc(a->pool, n * a->size);
        if (new_elts == NULL) {
            return NULL;
        }
        memcpy(new_elts, a->elts, a->nelts * a->size);
        a->elts = new_elts;
        a->nalloc = n;
    }
    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;
    return elt;
}

/* --- string helpers (verbatim nginx semantics) --- */
#define ngx_memcpy(d, s, n)        memcpy(d, s, n)
#define ngx_memcmp(a, b, n)        memcmp(a, b, n)
#define ngx_cpymem(d, s, n)        ((u_char *) memcpy(d, s, n) + (n))
#define ngx_strlen(s)              strlen((const char *)(s))
#define ngx_strncmp(s1, s2, n)     strncmp((const char *)(s1), (const char *)(s2), n)

static int
ngx_strncasecmp(u_char *s1, u_char *s2, size_t n)
{
    while (n) {
        u_char c1 = *s1++, c2 = *s2++;
        if (c1 >= 'A' && c1 <= 'Z') c1 |= 0x20;
        if (c2 >= 'A' && c2 <= 'Z') c2 |= 0x20;
        if (c1 != c2) {
            return c1 < c2 ? -1 : 1;
        }
        if (c1 == 0) {
            return 0;
        }
        n--;
    }
    return 0;
}

static u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {
        if (*p == c) {
            return p;
        }
        p++;
    }
    return NULL;
}

/* ngx_string("literal") initialiser used in parse_url's scheme. */
#define ngx_string(str)   { sizeof(str) - 1, (u_char *) str }

static void
ngx_str_set_impl(ngx_str_t *s, const char *lit)
{
    s->len = strlen(lit);
    s->data = (u_char *) lit;
}
#define ngx_str_set(str, text)   ngx_str_set_impl(str, (const char *) text)

/* ngx_atoi / ngx_atoof over a (data,len) span — verbatim nginx semantics:
 * return NGX_ERROR on a non-digit or on overflow, else the value. */
static ngx_int_t
ngx_atoi(u_char *line, size_t n)
{
    ngx_int_t value, cutoff, cutlim;
    if (n == 0) {
        return NGX_ERROR;
    }
    cutoff = NGX_MAX_INT_T_VALUE / 10;
    cutlim = NGX_MAX_INT_T_VALUE % 10;
    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }
        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }
        value = value * 10 + (*line - '0');
    }
    return value;
}

static off_t
ngx_atoof(u_char *line, size_t n)
{
    off_t value, cutoff, cutlim;
    if (n == 0) {
        return NGX_ERROR;
    }
    cutoff = NGX_MAX_OFF_T_VALUE / 10;
    cutlim = NGX_MAX_OFF_T_VALUE % 10;
    for (value = 0; n--; line++) {
        if (*line < '0' || *line > '9') {
            return NGX_ERROR;
        }
        if (value >= cutoff && (value > cutoff || *line - '0' > cutlim)) {
            return NGX_ERROR;
        }
        value = value * 10 + (*line - '0');
    }
    return value;
}

/* --- ngx_buf_t surface the response parser reads --- */
typedef struct {
    u_char  *pos;
    u_char  *last;
    u_char  *start;
    u_char  *end;
} ngx_buf_t;

/* --- captured response header (mirror of ngx_autocert_acme.h) --- */
typedef struct {
    ngx_str_t  name;
    ngx_str_t  value;
} ngx_autocert_acme_header_t;

/*
 * Reduced ngx_autocert_acme_request_t: ONLY the fields the sliced parser
 * functions touch, with identical names/types/order-independent semantics.
 * (The real struct also carries client/peer/resolve/ssl/send/timers, none of
 * which the parser functions reference.)
 */
typedef struct ngx_autocert_acme_request_s  ngx_autocert_acme_request_t;
struct ngx_autocert_acme_request_s {
    ngx_pool_t  *pool;
    ngx_log_t   *log;

    ngx_str_t    url;
    ngx_str_t    host;
    in_port_t    port;
    ngx_str_t    uri;

    ngx_uint_t   status;
    ngx_str_t    body_out;

    ngx_array_t *headers;

    ngx_buf_t   *recv;

    ngx_uint_t   headers_done;
    ngx_uint_t   chunked;
    off_t        content_length;
    size_t       body_offset;
    size_t       dechunk_pos;
    size_t       dechunk_total;
};

/*
 * Forward prototypes for the sliced static parser functions. The slice keeps
 * source order (parse_response is emitted before dechunk but calls it), so a
 * forward declaration is required — the production .c has the same prototypes
 * near its top. The harness (test or fuzzer) calls parse_url / parse_response /
 * header / memmem directly; declaring all of them here also silences
 * -Wunused-function for the ones a given harness doesn't call.
 */
static ngx_int_t ngx_autocert_acme_url_part_safe(ngx_str_t *s);
static ngx_int_t ngx_autocert_acme_parse_url(ngx_autocert_acme_request_t *r);
static u_char *ngx_autocert_memmem(u_char *hay, size_t n, const char *needle,
    size_t m);
static ngx_int_t ngx_autocert_acme_parse_response(
    ngx_autocert_acme_request_t *r);
static ngx_int_t ngx_autocert_acme_dechunk(ngx_autocert_acme_request_t *r);
/* ngx_autocert_acme_header is public (non-static) in the source. */
ngx_str_t *ngx_autocert_acme_header(ngx_autocert_acme_request_t *r,
    const char *name);

#endif /* NGX_AUTOCERT_HTTP_FUZZ_SHIM_H */
