/*
 * Unit tests for ngx_autocert_alpn (M10b) — the tls-alpn-01 challenge cert
 * store. Sibling of test_challenge: same in-process slab arena, same forced
 * crc32 collision (see test_slab.h), but a two-part {cert,key} value.
 *
 * Verifies:
 *   - set -> get round-trips both cert and key
 *   - set on an existing domain replaces both values
 *   - remove -> get returns NGX_DECLINED; remove of an absent domain is OK
 *   - bounds: domain / cert / key each rejected at len 0 and len > MAX
 *   - three domains incl. a forced crc32 collision pair, all retrievable
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include "test_slab.h"

#include "../../src/ngx_autocert_alpn.h"

#include <stdio.h>


static int          failures;
static ngx_pool_t  *pool;
/* Pass a zero-initialised log (log_level 0) so ngx_log_debug*() stay no-ops
 * in --with-debug builds instead of dereferencing a NULL log (segfault). */
static ngx_log_t   test_log;

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

static int
eq(ngx_str_t *s, ngx_str_t *lit)
{
    return s->len == lit->len && ngx_memcmp(s->data, lit->data, s->len) == 0;
}


static void
test_roundtrip(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom  = S("le.example.com");
    ngx_str_t  cert = S("-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----\n");
    ngx_str_t  key  = S("-----BEGIN PRIVATE KEY-----\nMIGH...\n-----END PRIVATE KEY-----\n");
    ngx_str_t  oc, ok;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &cert, &key) == NGX_OK, "set domain");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &dom, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &cert) && eq(&ok, &key),
          "get returns the stored cert + key");
}


static void
test_replace(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom = S("replace.example.org");
    ngx_str_t  c1 = S("cert-v1");
    ngx_str_t  k1 = S("key-v1");
    ngx_str_t  c2 = S("cert-version-two-longer");
    ngx_str_t  k2 = S("key-version-two-longer");
    ngx_str_t  oc, ok;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &c1, &k1) == NGX_OK, "set v1");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &c2, &k2) == NGX_OK,
          "set v2 (replace)");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &dom, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &c2) && eq(&ok, &k2),
          "get returns the replacement cert + key");
}


static void
test_remove(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom = S("remove.example.net");
    ngx_str_t  c = S("c");
    ngx_str_t  k = S("k");
    ngx_str_t  oc, ok;

    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &k) == NGX_OK, "set");
    CHECK(ngx_autocert_alpn_remove(zone, &dom) == NGX_OK, "remove present");
    CHECK(ngx_autocert_alpn_get(zone, &dom, pool, &oc, &ok) == NGX_DECLINED,
          "get after remove -> DECLINED");

    {
        ngx_str_t absent = S("never.example");
        CHECK(ngx_autocert_alpn_remove(zone, &absent) == NGX_OK,
              "remove absent -> OK");
    }
}


static void
test_bounds(ngx_shm_zone_t *zone)
{
    ngx_str_t  dom = S("bounds.example");
    ngx_str_t  c = S("c");
    ngx_str_t  k = S("k");
    ngx_str_t  empty = SL((u_char *) "x", 0);
    ngx_str_t  oc, ok;
    u_char     dbuf[NGX_AUTOCERT_ALPN_DOMAIN_MAX + 8];
    u_char     cbuf[NGX_AUTOCERT_ALPN_CERT_MAX + 8];
    u_char     kbuf[NGX_AUTOCERT_ALPN_KEY_MAX + 8];
    ngx_str_t  overd, overc, overk;

    CHECK(ngx_autocert_alpn_set(zone, &empty, &c, &k) == NGX_ERROR,
          "set rejects empty domain");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &empty, &k) == NGX_ERROR,
          "set rejects empty cert");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &empty) == NGX_ERROR,
          "set rejects empty key");

    memset(dbuf, 'd', sizeof(dbuf));
    memset(cbuf, 'c', sizeof(cbuf));
    memset(kbuf, 'k', sizeof(kbuf));
    overd = SL(dbuf, NGX_AUTOCERT_ALPN_DOMAIN_MAX + 1);
    overc = SL(cbuf, NGX_AUTOCERT_ALPN_CERT_MAX + 1);
    overk = SL(kbuf, NGX_AUTOCERT_ALPN_KEY_MAX + 1);

    CHECK(ngx_autocert_alpn_set(zone, &overd, &c, &k) == NGX_ERROR,
          "set rejects over-long domain");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &overc, &k) == NGX_ERROR,
          "set rejects over-long cert");
    CHECK(ngx_autocert_alpn_set(zone, &dom, &c, &overk) == NGX_ERROR,
          "set rejects over-long key");

    /* get/remove of an over-long domain bounce too */
    CHECK(ngx_autocert_alpn_get(zone, &overd, pool, &oc, &ok) == NGX_DECLINED,
          "get rejects over-long domain");
    CHECK(ngx_autocert_alpn_remove(zone, &overd) == NGX_OK,
          "remove of over-long domain -> OK (no-op)");
}


static void
test_three_and_collision(ngx_shm_zone_t *zone)
{
    u_char     a[NGX_AUTOCERT_TEST_COLL_LEN], b[NGX_AUTOCERT_TEST_COLL_LEN];
    ngx_str_t  d1 = S("first.example");
    ngx_str_t  c1 = S("cert-1");
    ngx_str_t  k1 = S("key-1");
    ngx_str_t  da, db, ca, ka, cb, kb, oc, ok;

    /* A plain third domain plus the two colliding ones => >= 3 entries. */
    CHECK(ngx_autocert_alpn_set(zone, &d1, &c1, &k1) == NGX_OK, "set domain 1");

    if (!ngx_autocert_test_crc32_collision(a, b)) {
        CHECK(0, "could not find a crc32 collision (unexpected)");
        return;
    }

    da = SL(a, NGX_AUTOCERT_TEST_COLL_LEN);
    db = SL(b, NGX_AUTOCERT_TEST_COLL_LEN);
    ca = S("cert-A"); ka = S("key-A");
    cb = S("cert-B-different"); kb = S("key-B-different");

    CHECK(ngx_crc32_long(a, NGX_AUTOCERT_TEST_COLL_LEN)
          == ngx_crc32_long(b, NGX_AUTOCERT_TEST_COLL_LEN),
          "two domains share a crc32 (forced collision)");

    CHECK(ngx_autocert_alpn_set(zone, &da, &ca, &ka) == NGX_OK,
          "collision: set domain A");
    CHECK(ngx_autocert_alpn_set(zone, &db, &cb, &kb) == NGX_OK,
          "collision: set domain B");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &da, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &ca) && eq(&ok, &ka),
          "collision: A retrievable with its own cert/key");

    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &db, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &cb) && eq(&ok, &kb),
          "collision: B retrievable with its own cert/key");

    /* first domain still intact alongside the collision pair */
    oc.len = 0; oc.data = NULL; ok.len = 0; ok.data = NULL;
    CHECK(ngx_autocert_alpn_get(zone, &d1, pool, &oc, &ok) == NGX_OK
          && eq(&oc, &c1) && eq(&ok, &k1),
          "third domain unaffected by the collision pair");
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

    pool = ngx_create_pool(16 * 1024, &test_log);
    if (pool == NULL) {
        fprintf(stderr, "FAIL: pool\n");
        return 2;
    }

    zone = ngx_autocert_test_zone_create();
    if (zone == NULL) {
        fprintf(stderr, "FAIL: slab zone create\n");
        return 2;
    }

    if (ngx_autocert_alpn_init_zone(zone, NULL) != NGX_OK) {
        fprintf(stderr, "FAIL: alpn init zone\n");
        return 2;
    }

    test_roundtrip(zone);
    test_replace(zone);
    test_remove(zone);
    test_bounds(zone);
    test_three_and_collision(zone);

    ngx_autocert_test_zone_destroy();
    ngx_destroy_pool(pool);

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
