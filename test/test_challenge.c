/*
 * Unit tests for ngx_autocert_challenge (M5) — the HTTP-01 token store.
 *
 * Standalone harness: links the challenge TU against an nginx build tree
 * (ngx_slab / ngx_rbtree / ngx_crc32 / ngx_shmtx + the base pool/string objs)
 * over an in-process malloc'd slab arena (see test_slab.h). No running server,
 * no shared memory — single-process so the slab mutex takes its uncontended
 * fast path. Verifies:
 *   - set -> get round-trips the keyauth
 *   - set on an existing token replaces the value (and frees the old blob)
 *   - remove -> get returns NGX_DECLINED; remove of an absent token is OK
 *   - bounds: len 0 and len > MAX are rejected
 *   - two tokens forced to the SAME crc32 (collision) are both retrievable,
 *     i.e. the full-token compare on a hash tie works
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "test_slab.h"

#include "../src/ngx_autocert_challenge.h"

#include <stdio.h>


static int          failures;
static ngx_pool_t  *pool;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


static ngx_str_t
S(const char *lit)
{
    ngx_str_t s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return s;
}

static ngx_str_t
SL(u_char *data, size_t len)
{
    ngx_str_t s;
    s.data = data;
    s.len = len;
    return s;
}


/*
 * Find two DISTINCT, equal-length byte strings that collide under
 * ngx_crc32_long. Targeting a fixed hash over 4 bytes would need ~2^32 tries;
 * instead we look for ANY collision (birthday) among 4-byte strings whose low
 * 24 bits index a seen-table — a match is near-certain within a few thousand
 * probes, and entirely deterministic for this fixed scan order.
 *
 * Returns 1 and fills a/b (length 4) on success, 0 if none found in the budget.
 */
#define COLL_LEN  NGX_AUTOCERT_TEST_COLL_LEN


static void
test_roundtrip(ngx_shm_zone_t *zone)
{
    ngx_str_t  tok = S("token-abc-123");
    ngx_str_t  ka  = S("token-abc-123.thumbprint-xyz");
    ngx_str_t  out;

    CHECK(ngx_autocert_challenge_set(zone, &tok, &ka) == NGX_OK,
          "set token");

    out.len = 0; out.data = NULL;
    CHECK(ngx_autocert_challenge_get(zone, &tok, pool, &out) == NGX_OK
          && out.len == ka.len
          && ngx_memcmp(out.data, ka.data, ka.len) == 0,
          "get returns the stored keyauth");
}


static void
test_replace(ngx_shm_zone_t *zone)
{
    ngx_str_t  tok = S("replace-me");
    ngx_str_t  ka1 = S("first-value");
    ngx_str_t  ka2 = S("second-much-longer-value-here");
    ngx_str_t  out;

    CHECK(ngx_autocert_challenge_set(zone, &tok, &ka1) == NGX_OK, "set v1");
    CHECK(ngx_autocert_challenge_set(zone, &tok, &ka2) == NGX_OK,
          "set v2 (replace)");

    out.len = 0; out.data = NULL;
    CHECK(ngx_autocert_challenge_get(zone, &tok, pool, &out) == NGX_OK
          && out.len == ka2.len
          && ngx_memcmp(out.data, ka2.data, ka2.len) == 0,
          "get returns the replacement value");
}


static void
test_remove(ngx_shm_zone_t *zone)
{
    ngx_str_t  tok = S("remove-me");
    ngx_str_t  ka  = S("value");
    ngx_str_t  out;

    CHECK(ngx_autocert_challenge_set(zone, &tok, &ka) == NGX_OK, "set");
    CHECK(ngx_autocert_challenge_remove(zone, &tok) == NGX_OK, "remove present");
    CHECK(ngx_autocert_challenge_get(zone, &tok, pool, &out) == NGX_DECLINED,
          "get after remove -> DECLINED");

    /* Removing an absent token is a no-op success. */
    {
        ngx_str_t absent = S("never-existed");
        CHECK(ngx_autocert_challenge_remove(zone, &absent) == NGX_OK,
              "remove absent -> OK");
    }
}


static void
test_bounds(ngx_shm_zone_t *zone)
{
    ngx_str_t  empty = SL((u_char *) "x", 0);   /* len 0 */
    ngx_str_t  ka    = S("value");
    ngx_str_t  out;
    u_char     big[NGX_AUTOCERT_TOKEN_MAX + 8];
    ngx_str_t  over;

    CHECK(ngx_autocert_challenge_set(zone, &empty, &ka) == NGX_ERROR,
          "set rejects empty token");

    memset(big, 'a', sizeof(big));
    over = SL(big, NGX_AUTOCERT_TOKEN_MAX + 1);
    CHECK(ngx_autocert_challenge_set(zone, &over, &ka) == NGX_ERROR,
          "set rejects over-long token");

    /* keyauth bounds */
    {
        ngx_str_t tok = S("tok");
        ngx_str_t emptyka = SL((u_char *) "x", 0);
        ngx_str_t bigka;
        u_char    kbuf[NGX_AUTOCERT_KEYAUTH_MAX + 8];

        CHECK(ngx_autocert_challenge_set(zone, &tok, &emptyka) == NGX_ERROR,
              "set rejects empty keyauth");
        memset(kbuf, 'k', sizeof(kbuf));
        bigka = SL(kbuf, NGX_AUTOCERT_KEYAUTH_MAX + 1);
        CHECK(ngx_autocert_challenge_set(zone, &tok, &bigka) == NGX_ERROR,
              "set rejects over-long keyauth");
    }

    /* get/remove of an over-long token bounce too */
    CHECK(ngx_autocert_challenge_get(zone, &over, pool, &out) == NGX_DECLINED,
          "get rejects over-long token");
    CHECK(ngx_autocert_challenge_remove(zone, &over) == NGX_OK,
          "remove of over-long token -> OK (no-op)");
}


static void
test_collision(ngx_shm_zone_t *zone)
{
    u_char     a[COLL_LEN], b[COLL_LEN];
    ngx_str_t  ta, tb, kaa, kab, out;

    if (!ngx_autocert_test_crc32_collision(a, b)) {
        CHECK(0, "could not find a crc32 collision (unexpected)");
        return;
    }

    ta = SL(a, COLL_LEN);
    tb = SL(b, COLL_LEN);
    kaa = S("value-for-A");
    kab = S("value-for-B-different");

    CHECK(ngx_crc32_long(a, COLL_LEN) == ngx_crc32_long(b, COLL_LEN),
          "two tokens share a crc32 (forced collision)");

    CHECK(ngx_autocert_challenge_set(zone, &ta, &kaa) == NGX_OK,
          "collision: set token A");
    CHECK(ngx_autocert_challenge_set(zone, &tb, &kab) == NGX_OK,
          "collision: set token B");

    out.len = 0; out.data = NULL;
    CHECK(ngx_autocert_challenge_get(zone, &ta, pool, &out) == NGX_OK
          && out.len == kaa.len
          && ngx_memcmp(out.data, kaa.data, kaa.len) == 0,
          "collision: A retrievable with its own value");

    out.len = 0; out.data = NULL;
    CHECK(ngx_autocert_challenge_get(zone, &tb, pool, &out) == NGX_OK
          && out.len == kab.len
          && ngx_memcmp(out.data, kab.data, kab.len) == 0,
          "collision: B retrievable with its own value");
}


int
main(void)
{
    ngx_shm_zone_t  *zone;

    ngx_time_init();
    ngx_autocert_test_globals();   /* pid + pagesize + cacheline + slab sizes */

    if (ngx_crc32_table_init() != NGX_OK) {
        fprintf(stderr, "FAIL: crc32 table init\n");
        return 2;
    }

    pool = ngx_create_pool(16 * 1024, NULL);
    if (pool == NULL) {
        fprintf(stderr, "FAIL: pool\n");
        return 2;
    }

    zone = ngx_autocert_test_zone_create();
    if (zone == NULL) {
        fprintf(stderr, "FAIL: slab zone create\n");
        return 2;
    }

    if (ngx_autocert_challenge_init_zone(zone, NULL) != NGX_OK) {
        fprintf(stderr, "FAIL: challenge init zone\n");
        return 2;
    }

    test_roundtrip(zone);
    test_replace(zone);
    test_remove(zone);
    test_bounds(zone);
    test_collision(zone);

    ngx_autocert_test_zone_destroy();
    ngx_destroy_pool(pool);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
