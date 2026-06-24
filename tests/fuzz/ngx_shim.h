/*
 * Minimal nginx surface for fuzzing the autocert JSON parser
 * (ngx_autocert_json_parse and accessors).
 *
 * The JSON parser reads attacker-influenceable bytes — ACME server responses
 * over a TLS channel, but still parsed defensively for correctness. It uses:
 *   - ngx_pool_t  (with a ->log field for ngx_log_debug1)
 *   - ngx_pcalloc / ngx_pnalloc
 *   - ngx_strncmp / ngx_strlen
 *   - ngx_log_debug1 (debug trace, no-op in fuzzing)
 *   - core types: u_char, ngx_int_t, ngx_uint_t, ngx_str_t
 *   - NGX_OK, NGX_ERROR, NGX_DECLINED
 *
 * Everything here is the faithful nginx surface those calls touch, reduced to
 * exactly the fields and semantics the sliced parser bodies use. The parser
 * bodies themselves are NOT copied — they are sliced from the shipped
 * src/ngx_autocert_json.c at build time by extract_parser.sh into
 * generated_json.inc, so the fuzzer always exercises production code with no
 * drift.
 */

#ifndef NGX_AUTOCERT_FUZZ_SHIM_H
#define NGX_AUTOCERT_FUZZ_SHIM_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* --- core types (nginx ngx_config.h) --- */
typedef intptr_t   ngx_int_t;
typedef uintptr_t  ngx_uint_t;
typedef unsigned char u_char;

/* nginx ngx_string.h */
typedef struct {
    size_t   len;
    u_char  *data;
} ngx_str_t;

/* --- core constants --- */
#define NGX_OK            0
#define NGX_ERROR        -1
#define NGX_AGAIN        -2
#define NGX_DECLINED     -5

#if (UINTPTR_MAX > 0xffffffffUL)
#define NGX_MAX_INT_T_VALUE  9223372036854775807LL
#else
#define NGX_MAX_INT_T_VALUE  2147483647
#endif

/* --- logging stubs ---
 * The parser calls ngx_log_debug1(level, log, err, fmt, arg).
 * In fuzzing we want complete silence; the macro expands to nothing.
 * We also need NGX_LOG_DEBUG_CORE to compile the call site.
 */
#define NGX_LOG_DEBUG_CORE  0

/* Stub ngx_log_t so pool->log is a valid (NULL) pointer field. */
typedef struct ngx_log_s  ngx_log_t;
struct ngx_log_s {
    int  dummy;
};

/* ngx_log_debug1 expands to nothing in the fuzzer — we don't need trace. */
#define ngx_log_debug1(level, log, err, fmt, arg1)   ((void)0)

/*
 * Pool shim. The parser allocates ngx_autocert_json_value_t,
 * ngx_autocert_json_member_t, ngx_autocert_json_element_t, and decoded string
 * buffers via ngx_pcalloc / ngx_pnalloc.  We back each alloc with malloc and
 * register it so the harness can free the lot after every input (otherwise
 * libFuzzer's leak check fires).  Nesting is bounded at 32 (NGX_AUTOCERT_JSON_
 * MAX_DEPTH); worst-case alloc count per input is bounded too, but we give a
 * generous registry so we never silently drop an alloc and leave a leak.
 */
#define NGX_FUZZ_POOL_MAX_ALLOCS  4096

typedef struct {
    void         *allocs[NGX_FUZZ_POOL_MAX_ALLOCS];
    size_t        nallocs;
    ngx_log_t    *log;        /* parser dereferences pool->log in macros */
} ngx_pool_t;

/* ngx_pcalloc: zeroing alloc (used for value/member/element nodes). */
static void *
ngx_pcalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    if (pool->nallocs >= NGX_FUZZ_POOL_MAX_ALLOCS) {
        return NULL;
    }
    p = calloc(1, size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs++] = p;
    return p;
}

/* ngx_pnalloc: non-zeroing alloc (used for decoded string buffers). */
static void *
ngx_pnalloc(ngx_pool_t *pool, size_t size)
{
    void *p;

    if (pool->nallocs >= NGX_FUZZ_POOL_MAX_ALLOCS) {
        return NULL;
    }
    p = malloc(size ? size : 1);
    if (p == NULL) {
        return NULL;
    }
    pool->allocs[pool->nallocs++] = p;
    return p;
}

/* Reset the pool: free all tracked allocs and zero the count. */
static void
ngx_fuzz_pool_reset(ngx_pool_t *pool)
{
    size_t  i;

    for (i = 0; i < pool->nallocs; i++) {
        free(pool->allocs[i]);
    }
    pool->nallocs = 0;
}

/* --- verbatim nginx string helpers --- */

/* ngx_strlen: verbatim nginx macro — accepts u_char* or char* without warning. */
#define ngx_strlen(s)  strlen((const char *)(s))

/* ngx_strncmp: strncmp over u_char/void */
#define ngx_strncmp(s1, s2, n)  strncmp((const char *)(s1), (const char *)(s2), n)

/*
 * The autocert_json_type enum and value/member/element structs live in
 * ngx_autocert_json.h, which we include directly (it needs only our shim
 * types above).  The .inc include that follows provides the parser function
 * bodies compiled against this shim rather than real nginx headers.
 *
 * ngx_autocert_json.h normally includes <ngx_config.h> and <ngx_core.h>;
 * the extract step strips those includes so the .inc is self-contained with
 * only our shim + the typed structs.
 */

#endif /* NGX_AUTOCERT_FUZZ_SHIM_H */
