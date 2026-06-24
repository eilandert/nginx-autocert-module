/*
 * Unit test for ngx_autocert_account_json_safe() (M4d) — the guard that rejects
 * bytes which would break the protected JWS JSON header (control chars < 0x20,
 * double-quote, backslash). The kid/nonce/url values it screens come straight
 * from ACME response headers, so a hostile/buggy server must not be able to
 * inject a field or corrupt the header.
 *
 * The function is static, so this TU slices JUST it from the shipped
 * src/ngx_autocert_account.c via tests/unit/extract_jsonsafe.sh (the whole .c is the
 * account state machine and would drag in the acme client + json + crypto TUs
 * to link). Locked to production code, no copy drift.
 *
 * Exit 0 = all pass; non-zero on first failure.
 */

#include <ngx_config.h>
#include <ngx_core.h>

#include "generated_jsonsafe.inc"

#include <stdio.h>
#include <string.h>


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


static ngx_uint_t
safe_lit(const char *lit)
{
    ngx_str_t s;
    s.data = (u_char *) lit;
    s.len = ngx_strlen(lit);
    return ngx_autocert_account_json_safe(&s);
}

static ngx_uint_t
safe_n(const u_char *data, size_t len)
{
    ngx_str_t s;
    s.data = (u_char *) data;
    s.len = len;
    return ngx_autocert_account_json_safe(&s);
}


int
main(void)
{
    ngx_uint_t  c;

    /* ordinary ACME tokens / URLs / nonces accepted */
    CHECK(safe_lit("https://acme.example/acme/acct/12345") == 1,
          "accepts an ordinary URL");
    CHECK(safe_lit("0123456789abcdef-_.~") == 1,
          "accepts a base64url-ish token");
    CHECK(safe_lit("") == 1, "accepts the empty string");
    CHECK(safe_lit("space and ~tilde!") == 1,
          "accepts spaces and printable punctuation");

    /* every control byte 0x00..0x1f rejected (one embedded in a token) */
    for (c = 0x00; c <= 0x1f; c++) {
        u_char  buf[5] = { 'a', 'b', (u_char) c, 'c', 'd' };
        char    msg[48];
        snprintf(msg, sizeof(msg), "rejects control byte 0x%02x", (unsigned) c);
        CHECK(safe_n(buf, sizeof(buf)) == 0, msg);
    }

    /* the two JSON-structural bytes rejected */
    CHECK(safe_lit("has\"quote") == 0, "rejects a double quote");
    CHECK(safe_lit("has\\backslash") == 0, "rejects a backslash");

    /* 0x7f (DEL) and high bytes are NOT rejected by this guard (only < 0x20,
     * '"' and '\\' are) — pin the exact contract so a future change is noticed. */
    {
        u_char  del[3] = { 'a', 0x7f, 'b' };
        u_char  hi[3]  = { 'a', 0xff, 'b' };
        CHECK(safe_n(del, sizeof(del)) == 1,
              "accepts 0x7f (DEL) — guard only screens <0x20, quote, backslash");
        CHECK(safe_n(hi, sizeof(hi)) == 1, "accepts a high byte (>= 0x80)");
    }

    if (failures) {
        fprintf(stderr, "\n%d test(s) FAILED\n", failures);
        return 1;
    }
    fprintf(stderr, "\nall tests passed\n");
    return 0;
}
