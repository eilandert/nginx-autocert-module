/*
 * libFuzzer harness for the autocert ACME HTTP-response parser
 * (ngx_autocert_acme_parse_response + ngx_autocert_acme_dechunk).
 *
 * Why this target: these functions read ACME server response BYTES — delivered
 * over verified TLS, but still attacker-influenceable (compromised CA, hostile
 * redirect, buggy server). The parser is written to never rely on a NUL
 * terminator and to honour the buffer length, but a single off-by-one in the
 * status-line scan, the header loop, the Content-Length / Transfer-Encoding
 * handling, or the chunk-size arithmetic in dechunk would be a worker-crashing
 * OOB read. Coverage-guided fuzzing catches that class; the e2e tests miss it.
 *
 * The real parser bodies live in ../../src/ngx_autocert_acme.c and depend on the
 * nginx event/SSL/resolver tree; tests/fuzz/extract_http.sh slices ONLY the
 * self-contained parser functions into generated_http.inc, compiled here
 * against tests/fuzz/ngx_http_shim.h. We always fuzz the SHIPPED code with no drift.
 *
 * The harness copies the input into a buffer sized EXACTLY to `size` (no
 * trailing NUL) so ASAN turns any read at/past the end into a heap-buffer-
 * overflow, and drives parse_response the way the read handler does: feed the
 * whole buffer in one shot (the parser re-scans the accumulated buffer each
 * call), then, if it asked for more, do nothing — a single call already covers
 * the status line + headers + body framing + dechunk paths over this input.
 *
 * Build (see tests/fuzz/build.sh):
 *   CC=clang bash tests/fuzz/build.sh     -> tests/fuzz/fuzz_http (ASan+UBSan+fuzzer)
 * Run:
 *   cd tests/fuzz && ./fuzz_http -max_total_time=120 corpus_http/
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ngx_http_shim.h"
#include "generated_http.inc"


int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ngx_pool_t                   pool;
    ngx_log_t                    log;
    ngx_autocert_acme_request_t  r;
    ngx_buf_t                    b;
    u_char                      *buf;

    log.dummy = 0;
    pool.nallocs = 0;
    pool.log = &log;

    /* Allocate EXACTLY `size` bytes (one when size == 0) with no NUL. */
    buf = (u_char *) malloc(size ? size : 1);
    if (buf == NULL) {
        return 0;
    }
    if (size) {
        memcpy(buf, data, size);
    }

    /* A request as the read handler hands to parse_response: recv buffer with
     * the accumulated bytes, content_length sentinel -1, nothing parsed yet. */
    memset(&r, 0, sizeof(r));
    r.pool = &pool;
    r.log = &log;
    r.content_length = -1;

    b.start = buf;
    b.pos = buf;
    b.last = buf + size;
    b.end = buf + size;
    r.recv = &b;

    /* Single shot over the whole buffer. parse_response internally dispatches
     * to dechunk for a chunked body, so this one call exercises both. The
     * return code is irrelevant to the fuzzer; we only care that no read
     * escapes [buf, buf+size). */
    (void) ngx_autocert_acme_parse_response(&r);

    /* If it parsed a chunked body to completion, the decoded bytes were
     * pool-allocated; touch them so ASAN validates that region too. */
    if (r.body_out.data != NULL && r.body_out.len > 0) {
        volatile u_char sink = 0;
        size_t          i;
        for (i = 0; i < r.body_out.len; i++) {
            sink ^= r.body_out.data[i];
        }
        (void) sink;
    }

    ngx_http_fuzz_pool_reset(&pool);
    free(buf);
    return 0;
}
