/*
 * libFuzzer harness for ngx_autocert_json_parse().
 *
 * The ACME helper parses CA-controlled JSON. The unit tests pin the expected
 * ACME shapes; this target throws arbitrary length-delimited bytes at the same
 * parser and a few accessors under ASan/UBSan.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "../src/ngx_autocert_json.h"

#include <stddef.h>
#include <stdint.h>

#define FUZZ_MAX_INPUT  (256 * 1024)

static ngx_uint_t initialized;

static void
init_once(void)
{
    if (!initialized) {
        ngx_time_init();
        initialized = 1;
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t                  *pool;
    u_char                      *buf;
    ngx_str_t                    s;
    ngx_int_t                    n;
    ngx_autocert_json_value_t   *root, *item;

    if (size > FUZZ_MAX_INPUT) {
        return 0;
    }

    init_once();

    pool = ngx_create_pool(64 * 1024, NULL);
    if (pool == NULL) {
        return 0;
    }

    buf = ngx_pnalloc(pool, size ? size : 1);
    if (buf == NULL) {
        ngx_destroy_pool(pool);
        return 0;
    }

    if (size != 0) {
        ngx_memcpy(buf, data, size);
    }

    root = ngx_autocert_json_parse(pool, buf, size);
    if (root != NULL) {
        (void) ngx_autocert_json_object_str(root, "newNonce", &s);
        (void) ngx_autocert_json_object_str(root, "newAccount", &s);
        (void) ngx_autocert_json_object_str(root, "newOrder", &s);
        (void) ngx_autocert_json_array_count(root);

        item = ngx_autocert_json_array_item(root, 0);
        if (item != NULL && item->type == NGX_AUTOCERT_JSON_NUMBER) {
            (void) ngx_autocert_json_number_int(item, &n);
        }
        if (root->type == NGX_AUTOCERT_JSON_NUMBER) {
            (void) ngx_autocert_json_number_int(root, &n);
        }
    }

    ngx_destroy_pool(pool);
    return 0;
}

volatile ngx_cycle_t  *ngx_cycle;

void
ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    const char *fmt, ...)
{
    (void) level;
    (void) log;
    (void) err;
    (void) fmt;
}
