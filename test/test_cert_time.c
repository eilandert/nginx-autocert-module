/*
 * Unit tests for the crypto TU's certificate-expiry helpers (M8 renewal):
 *   - ngx_http_autocert_cert_not_after(path, &out, &key_id) — read a leaf PEM's notAfter
 *     as a Unix epoch; ENOENT/ENOTDIR -> NGX_DECLINED, a symlinked path ->
 *     NGX_ERROR (O_NOFOLLOW), other failures -> NGX_ERROR.
 *   - ngx_autocert_timegm(struct tm*) — a self-contained, timezone-independent
 *     UTC tm -> time_t, exercised with a leap day and a year past 2038.
 *
 * ngx_autocert_timegm is static, so this TU include-shims the whole crypto .c
 * (the same source the server compiles) to reach it — no production hook and no
 * copy drift. The PEM fixture is test/fixture_leaf.pem (notAfter 2099-12-31
 * 23:59:59Z, epoch 4102444799 — past 2038 to exercise 64-bit time_t).
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* Log + cycle stubs the crypto TU references; define BEFORE including it. */
volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level; (void) log; (void) err; (void) fmt;
}

/* Include-shim: pulls in the static ngx_autocert_timegm + the public
 * ngx_http_autocert_cert_not_after, compiled exactly as shipped. */
#include "../src/ngx_http_autocert_crypto.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>


static int  failures;

#define CHECK(cond, msg)                                                      \
    do {                                                                      \
        if (!(cond)) {                                                        \
            fprintf(stderr, "FAIL: %s\n", msg);                               \
            failures++;                                                       \
        } else {                                                              \
            fprintf(stderr, "ok:   %s\n", msg);                               \
        }                                                                     \
    } while (0)


/* The committed fixture; epoch of its notAfter (2099-12-31T23:59:59Z). */
#define FIXTURE_PATH   "test/fixture_leaf.pem"
#define FIXTURE_EPOCH  ((time_t) 4102444799)


static void
test_timegm_vectors(void)
{
    struct tm  tm;

    struct {
        int  y, mon, mday, h, mi, s;
        time_t expect;
        const char *msg;
    } v[] = {
        /* epoch itself */
        { 1970,  1,  1,  0,  0,  0,          0, "timegm epoch 1970-01-01" },
        /* a known value: 2001-09-09T01:46:40Z == 1000000000 */
        { 2001,  9,  9,  1, 46, 40, 1000000000, "timegm 2001-09-09 == 1e9" },
        /* leap day 2024-02-29 (2024 IS a leap year) */
        { 2024,  2, 29, 12,  0,  0, 1709208000, "timegm leap day 2024-02-29" },
        /* A year past 2038: on a 64-bit time_t this must compute exactly (and
         * NOT be clamped to -1 by the 32-bit overflow guard); on a 32-bit
         * time_t the guard would return -1 instead of wrapping. 2099-12-31. */
        { 2099, 12, 31, 23, 59, 59, 4102444799, "timegm 2099 (> 2038)" },
    };
    size_t  i;

    for (i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        memset(&tm, 0, sizeof(tm));
        tm.tm_year = v[i].y - 1900;
        tm.tm_mon  = v[i].mon - 1;
        tm.tm_mday = v[i].mday;
        tm.tm_hour = v[i].h;
        tm.tm_min  = v[i].mi;
        tm.tm_sec  = v[i].s;
        CHECK(ngx_autocert_timegm(&tm) == v[i].expect, v[i].msg);
    }

    /* cross-check against libc timegm for a sweep of dates */
    {
        int  ok = 1;
        struct tm  t;
        time_t years[] = { 1971, 1999, 2000, 2016, 2038, 2040, 2100, 2400 };
        size_t k;
        for (k = 0; k < sizeof(years) / sizeof(years[0]); k++) {
            memset(&t, 0, sizeof(t));
            t.tm_year = (int) years[k] - 1900;
            t.tm_mon = 5; t.tm_mday = 15; t.tm_hour = 6;
            t.tm_min = 7; t.tm_sec = 8;
            if (ngx_autocert_timegm(&t) != timegm(&t)) {
                ok = 0;
            }
        }
        CHECK(ok, "timegm matches libc timegm across a year sweep");
    }

    /* out-of-range year => (time_t) -1 */
    memset(&tm, 0, sizeof(tm));
    tm.tm_year = 10000 - 1900;     /* y == 10000 > 9999 */
    tm.tm_mon = 0; tm.tm_mday = 1;
    CHECK(ngx_autocert_timegm(&tm) == (time_t) -1,
          "timegm rejects out-of-range year");
}


static void
test_cert_not_after(void)
{
    time_t  out = 0;
    int     key_id = EVP_PKEY_NONE;

    CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, &key_id) == NGX_OK
          && out == FIXTURE_EPOCH,
          "cert_not_after reads the fixture's exact notAfter epoch");

    /* The fixture leaf is EC (id-ecPublicKey); the key_id out-param reports it. */
    CHECK(key_id == EVP_PKEY_EC,
          "cert_not_after reports the leaf key family (EC) via key_id");

    /* key_id is optional: a NULL pointer must be accepted. */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after(FIXTURE_PATH, &out, NULL) == NGX_OK
          && out == FIXTURE_EPOCH,
          "cert_not_after accepts a NULL key_id out-param");

    /* Missing file -> NGX_DECLINED (no cert stored yet). */
    out = 0;
    CHECK(ngx_http_autocert_cert_not_after("test/does-not-exist.pem", &out, NULL)
              == NGX_DECLINED,
          "cert_not_after missing file -> NGX_DECLINED");

    /* Symlink to the fixture -> NGX_ERROR (O_NOFOLLOW refuses to traverse). */
    {
        char  link[] = "/tmp/autocert_test_link_XXXXXX";
        int   fd = mkstemp(link);
        char  abs_target[4096];

        if (fd != -1) {
            close(fd);
            unlink(link);
            if (realpath(FIXTURE_PATH, abs_target) != NULL
                && symlink(abs_target, link) == 0)
            {
                out = 0;
                CHECK(ngx_http_autocert_cert_not_after(link, &out, NULL) == NGX_ERROR,
                      "cert_not_after refuses to follow a symlink (O_NOFOLLOW)");
                unlink(link);
            } else {
                CHECK(0, "could not set up symlink fixture");
            }
        } else {
            CHECK(0, "could not create temp path for symlink fixture");
        }
    }
}


int
main(void)
{
    /* timegm path needs ngx_time initialised? It does not, but harmless. */
    ngx_time_init();

    test_timegm_vectors();
    test_cert_not_after();

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
