/*
 * ngx_autocert_json — minimal JSON reader for ACME responses (M4c).
 * See ngx_autocert_json.h for the contract.
 *
 * Recursive-descent over a length-delimited byte buffer (no NUL needed). Every
 * value is pool-allocated; nesting is bounded so a hostile deeply-nested
 * document cannot blow the C stack. The grammar follows RFC 8259.
 */

#include "ngx_autocert_json.h"


/*
 * Max object/array nesting. ACME documents are shallow (directory → meta is the
 * deepest at ~2; orders nest authorizations/challenges a few levels). 32 is far
 * above anything real and keeps the recursion bounded for untrusted input.
 */
#define NGX_AUTOCERT_JSON_MAX_DEPTH  32


typedef struct {
    u_char      *p;       /* next unread byte */
    u_char      *last;    /* one past the end */
    ngx_pool_t  *pool;
    ngx_uint_t   depth;
} ngx_autocert_json_ctx_t;


static ngx_autocert_json_value_t *ngx_autocert_json_value(
    ngx_autocert_json_ctx_t *c);
static ngx_autocert_json_value_t *ngx_autocert_json_object(
    ngx_autocert_json_ctx_t *c);
static ngx_autocert_json_value_t *ngx_autocert_json_array(
    ngx_autocert_json_ctx_t *c);
static ngx_int_t ngx_autocert_json_string_raw(ngx_autocert_json_ctx_t *c,
    ngx_str_t *out);
static ngx_autocert_json_value_t *ngx_autocert_json_number(
    ngx_autocert_json_ctx_t *c);
static ngx_autocert_json_value_t *ngx_autocert_json_literal(
    ngx_autocert_json_ctx_t *c);


static void
ngx_autocert_json_skip_ws(ngx_autocert_json_ctx_t *c)
{
    while (c->p < c->last) {
        switch (*c->p) {
        case ' ': case '\t': case '\n': case '\r':
            c->p++;
            continue;
        default:
            return;
        }
    }
}


static ngx_autocert_json_value_t *
ngx_autocert_json_alloc(ngx_autocert_json_ctx_t *c,
    ngx_autocert_json_type_e type)
{
    ngx_autocert_json_value_t  *v;

    v = ngx_pcalloc(c->pool, sizeof(ngx_autocert_json_value_t));
    if (v != NULL) {
        v->type = type;
    }
    return v;
}


ngx_autocert_json_value_t *
ngx_autocert_json_parse(ngx_pool_t *pool, u_char *data, size_t len)
{
    ngx_autocert_json_ctx_t     c;
    ngx_autocert_json_value_t  *v;

    if (data == NULL || len == 0) {
        return NULL;
    }

    c.p = data;
    c.last = data + len;
    c.pool = pool;
    c.depth = 0;

    ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                   "autocert: json parse start, %uz bytes", len);

    ngx_autocert_json_skip_ws(&c);

    v = ngx_autocert_json_value(&c);
    if (v == NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                       "autocert: json parse failed at offset %z",
                       (ssize_t) (c.p - data));
        return NULL;
    }

    /* Whole input must be a single value; only trailing whitespace allowed. */
    ngx_autocert_json_skip_ws(&c);
    if (c.p != c.last) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, pool->log, 0,
                       "autocert: json trailing data at offset %z",
                       (ssize_t) (c.p - data));
        return NULL;
    }

    return v;
}


static ngx_autocert_json_value_t *
ngx_autocert_json_value(ngx_autocert_json_ctx_t *c)
{
    if (c->p >= c->last) {
        return NULL;
    }

    switch (*c->p) {

    case '{':
        return ngx_autocert_json_object(c);

    case '[':
        return ngx_autocert_json_array(c);

    case '"':
        {
            ngx_autocert_json_value_t  *v;

            v = ngx_autocert_json_alloc(c, NGX_AUTOCERT_JSON_STRING);
            if (v == NULL
                || ngx_autocert_json_string_raw(c, &v->u.string) != NGX_OK)
            {
                return NULL;
            }
            return v;
        }

    case '-':
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return ngx_autocert_json_number(c);

    case 't': case 'f': case 'n':
        return ngx_autocert_json_literal(c);

    default:
        return NULL;
    }
}


static ngx_autocert_json_value_t *
ngx_autocert_json_object(ngx_autocert_json_ctx_t *c)
{
    ngx_autocert_json_value_t   *v;
    ngx_autocert_json_member_t  *m, **tail;

    if (++c->depth > NGX_AUTOCERT_JSON_MAX_DEPTH) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->pool->log, 0,
                       "autocert: json object exceeds max depth %ui",
                       (ngx_uint_t) NGX_AUTOCERT_JSON_MAX_DEPTH);
        return NULL;
    }

    v = ngx_autocert_json_alloc(c, NGX_AUTOCERT_JSON_OBJECT);
    if (v == NULL) {
        return NULL;
    }

    c->p++;                                   /* consume '{' */
    tail = &v->u.members;

    ngx_autocert_json_skip_ws(c);
    if (c->p < c->last && *c->p == '}') {     /* empty object */
        c->p++;
        c->depth--;
        return v;
    }

    for ( ;; ) {
        ngx_autocert_json_skip_ws(c);
        if (c->p >= c->last || *c->p != '"') {
            return NULL;                      /* key must be a string */
        }

        m = ngx_pcalloc(c->pool, sizeof(ngx_autocert_json_member_t));
        if (m == NULL || ngx_autocert_json_string_raw(c, &m->name) != NGX_OK) {
            return NULL;
        }

        ngx_autocert_json_skip_ws(c);
        if (c->p >= c->last || *c->p != ':') {
            return NULL;
        }
        c->p++;                               /* consume ':' */

        ngx_autocert_json_skip_ws(c);
        m->value = ngx_autocert_json_value(c);
        if (m->value == NULL) {
            return NULL;
        }

        *tail = m;
        tail = &m->next;

        ngx_autocert_json_skip_ws(c);
        if (c->p >= c->last) {
            return NULL;
        }
        if (*c->p == ',') {
            c->p++;
            continue;
        }
        if (*c->p == '}') {
            c->p++;
            c->depth--;
            return v;
        }
        return NULL;
    }
}


static ngx_autocert_json_value_t *
ngx_autocert_json_array(ngx_autocert_json_ctx_t *c)
{
    ngx_autocert_json_value_t    *v;
    ngx_autocert_json_element_t  *e, **tail;

    if (++c->depth > NGX_AUTOCERT_JSON_MAX_DEPTH) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, c->pool->log, 0,
                       "autocert: json array exceeds max depth %ui",
                       (ngx_uint_t) NGX_AUTOCERT_JSON_MAX_DEPTH);
        return NULL;
    }

    v = ngx_autocert_json_alloc(c, NGX_AUTOCERT_JSON_ARRAY);
    if (v == NULL) {
        return NULL;
    }

    c->p++;                                   /* consume '[' */
    tail = &v->u.elements;

    ngx_autocert_json_skip_ws(c);
    if (c->p < c->last && *c->p == ']') {     /* empty array */
        c->p++;
        c->depth--;
        return v;
    }

    for ( ;; ) {
        ngx_autocert_json_skip_ws(c);

        e = ngx_pcalloc(c->pool, sizeof(ngx_autocert_json_element_t));
        if (e == NULL) {
            return NULL;
        }
        e->value = ngx_autocert_json_value(c);
        if (e->value == NULL) {
            return NULL;
        }

        *tail = e;
        tail = &e->next;

        ngx_autocert_json_skip_ws(c);
        if (c->p >= c->last) {
            return NULL;
        }
        if (*c->p == ',') {
            c->p++;
            continue;
        }
        if (*c->p == ']') {
            c->p++;
            c->depth--;
            return v;
        }
        return NULL;
    }
}


/* Append one UTF-8-encoded code point to *p (p has room: <=4 bytes). */
static u_char *
ngx_autocert_json_utf8(u_char *p, uint32_t cp)
{
    if (cp < 0x80) {
        *p++ = (u_char) cp;

    } else if (cp < 0x800) {
        *p++ = (u_char) (0xc0 | (cp >> 6));
        *p++ = (u_char) (0x80 | (cp & 0x3f));

    } else if (cp < 0x10000) {
        *p++ = (u_char) (0xe0 | (cp >> 12));
        *p++ = (u_char) (0x80 | ((cp >> 6) & 0x3f));
        *p++ = (u_char) (0x80 | (cp & 0x3f));

    } else {
        *p++ = (u_char) (0xf0 | (cp >> 18));
        *p++ = (u_char) (0x80 | ((cp >> 12) & 0x3f));
        *p++ = (u_char) (0x80 | ((cp >> 6) & 0x3f));
        *p++ = (u_char) (0x80 | (cp & 0x3f));
    }

    return p;
}


/* Read 4 hex digits at c->p into *out (0..0xffff). c->p advanced past them. */
static ngx_int_t
ngx_autocert_json_hex4(ngx_autocert_json_ctx_t *c, uint32_t *out)
{
    uint32_t  v;
    ngx_uint_t  i;
    u_char    ch;

    if (c->last - c->p < 4) {
        return NGX_ERROR;
    }

    v = 0;
    for (i = 0; i < 4; i++) {
        ch = *c->p++;
        v <<= 4;
        if (ch >= '0' && ch <= '9') {
            v |= (uint32_t) (ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            v |= (uint32_t) (ch - 'a' + 10);
        } else if (ch >= 'A' && ch <= 'F') {
            v |= (uint32_t) (ch - 'A' + 10);
        } else {
            return NGX_ERROR;
        }
    }

    *out = v;
    return NGX_OK;
}


/*
 * Parse a JSON string starting at c->p (which points at the opening '"'),
 * decoding escapes into a fresh pool buffer. The decoded form is never longer
 * than the source span, so one allocation of (span length) bytes always fits.
 */
static ngx_int_t
ngx_autocert_json_string_raw(ngx_autocert_json_ctx_t *c, ngx_str_t *out)
{
    u_char    *start, *dst, ch;
    uint32_t   cp, lo;

    c->p++;                                   /* consume opening '"' */
    start = c->p;

    /*
     * Worst case the decoded string equals the raw span between the quotes;
     * escapes only shrink it (\n -> 1 byte, \uXXXX -> <=3 bytes). Allocate the
     * span up front. last - start is an upper bound even with the closing
     * quote not yet found.
     */
    dst = ngx_pnalloc(c->pool, (size_t) (c->last - start));
    if (dst == NULL && c->last != start) {
        return NGX_ERROR;
    }
    out->data = dst;

    while (c->p < c->last) {
        ch = *c->p++;

        if (ch == '"') {                      /* end of string */
            out->len = (size_t) (dst - out->data);
            return NGX_OK;
        }

        if (ch < 0x20) {                      /* control chars must be escaped */
            return NGX_ERROR;
        }

        if (ch != '\\') {
            *dst++ = ch;
            continue;
        }

        /* escape sequence */
        if (c->p >= c->last) {
            return NGX_ERROR;
        }
        ch = *c->p++;

        switch (ch) {
        case '"':  *dst++ = '"';  break;
        case '\\': *dst++ = '\\'; break;
        case '/':  *dst++ = '/';  break;
        case 'b':  *dst++ = '\b'; break;
        case 'f':  *dst++ = '\f'; break;
        case 'n':  *dst++ = '\n'; break;
        case 'r':  *dst++ = '\r'; break;
        case 't':  *dst++ = '\t'; break;

        case 'u':
            if (ngx_autocert_json_hex4(c, &cp) != NGX_OK) {
                return NGX_ERROR;
            }

            if (cp >= 0xd800 && cp <= 0xdbff) {
                /* high surrogate — must be followed by \uXXXX low surrogate */
                if (c->last - c->p < 2 || c->p[0] != '\\' || c->p[1] != 'u') {
                    return NGX_ERROR;
                }
                c->p += 2;
                if (ngx_autocert_json_hex4(c, &lo) != NGX_OK) {
                    return NGX_ERROR;
                }
                if (lo < 0xdc00 || lo > 0xdfff) {
                    return NGX_ERROR;       /* not a low surrogate */
                }
                cp = 0x10000
                     + (((cp - 0xd800) << 10) | (lo - 0xdc00));

            } else if (cp >= 0xdc00 && cp <= 0xdfff) {
                return NGX_ERROR;           /* lone low surrogate */
            }

            dst = ngx_autocert_json_utf8(dst, cp);
            break;

        default:
            return NGX_ERROR;               /* invalid escape */
        }
    }

    return NGX_ERROR;                         /* unterminated string */
}


static ngx_autocert_json_value_t *
ngx_autocert_json_number(ngx_autocert_json_ctx_t *c)
{
    ngx_autocert_json_value_t  *v;
    u_char                     *start;
    ngx_uint_t                  digits;

    start = c->p;

    if (c->p < c->last && *c->p == '-') {
        c->p++;
    }

    /* int part: 0 alone, or [1-9][0-9]* */
    if (c->p >= c->last) {
        return NULL;
    }
    if (*c->p == '0') {
        c->p++;
    } else if (*c->p >= '1' && *c->p <= '9') {
        while (c->p < c->last && *c->p >= '0' && *c->p <= '9') {
            c->p++;
        }
    } else {
        return NULL;
    }

    /* fraction */
    if (c->p < c->last && *c->p == '.') {
        c->p++;
        digits = 0;
        while (c->p < c->last && *c->p >= '0' && *c->p <= '9') {
            c->p++;
            digits++;
        }
        if (digits == 0) {
            return NULL;
        }
    }

    /* exponent */
    if (c->p < c->last && (*c->p == 'e' || *c->p == 'E')) {
        c->p++;
        if (c->p < c->last && (*c->p == '+' || *c->p == '-')) {
            c->p++;
        }
        digits = 0;
        while (c->p < c->last && *c->p >= '0' && *c->p <= '9') {
            c->p++;
            digits++;
        }
        if (digits == 0) {
            return NULL;
        }
    }

    v = ngx_autocert_json_alloc(c, NGX_AUTOCERT_JSON_NUMBER);
    if (v == NULL) {
        return NULL;
    }
    v->u.number.data = start;
    v->u.number.len = (size_t) (c->p - start);
    return v;
}


static ngx_autocert_json_value_t *
ngx_autocert_json_literal(ngx_autocert_json_ctx_t *c)
{
    static const struct {
        const char                *text;
        size_t                     len;
        ngx_autocert_json_type_e   type;
        ngx_uint_t                 boolean;
    } lits[] = {
        { "true",  4, NGX_AUTOCERT_JSON_BOOL, 1 },
        { "false", 5, NGX_AUTOCERT_JSON_BOOL, 0 },
        { "null",  4, NGX_AUTOCERT_JSON_NULL, 0 },
    };

    ngx_autocert_json_value_t  *v;
    ngx_uint_t                  i;

    for (i = 0; i < sizeof(lits) / sizeof(lits[0]); i++) {
        if ((size_t) (c->last - c->p) >= lits[i].len
            && ngx_strncmp(c->p, lits[i].text, lits[i].len) == 0)
        {
            c->p += lits[i].len;
            v = ngx_autocert_json_alloc(c, lits[i].type);
            if (v == NULL) {
                return NULL;
            }
            v->u.boolean = lits[i].boolean;
            return v;
        }
    }

    return NULL;
}


/*
 * Look up a member by key. Members are kept in document order, so on a
 * duplicate key (RFC 8259 allows but does not define them) this returns the
 * FIRST occurrence — "first wins". ACME responses never legitimately repeat a
 * key; a hostile/buggy CA cannot use a trailing duplicate to override a value
 * the parser already read.
 */
ngx_autocert_json_value_t *
ngx_autocert_json_object_get(ngx_autocert_json_value_t *v, const char *key)
{
    ngx_autocert_json_member_t  *m;
    size_t                       klen;

    if (v == NULL || v->type != NGX_AUTOCERT_JSON_OBJECT) {
        return NULL;
    }

    klen = ngx_strlen(key);

    for (m = v->u.members; m != NULL; m = m->next) {
        if (m->name.len == klen
            && ngx_strncmp(m->name.data, key, klen) == 0)
        {
            return m->value;
        }
    }

    return NULL;
}


/*
 * Fetch a STRING member as an ngx_str_t (length-counted, NOT NUL-terminated).
 * A JSON string value may contain interior NUL bytes (a "\u0000" escape), so
 * callers must treat *out as len-bounded and never strlen() it. NGX_DECLINED =
 * key absent, NGX_ERROR = present but not a string.
 */
ngx_int_t
ngx_autocert_json_object_str(ngx_autocert_json_value_t *v, const char *key,
    ngx_str_t *out)
{
    ngx_autocert_json_value_t  *m;

    if (v == NULL || v->type != NGX_AUTOCERT_JSON_OBJECT) {
        return NGX_ERROR;
    }

    m = ngx_autocert_json_object_get(v, key);
    if (m == NULL) {
        return NGX_DECLINED;
    }
    if (m->type != NGX_AUTOCERT_JSON_STRING) {
        return NGX_ERROR;
    }

    *out = m->u.string;
    return NGX_OK;
}


ngx_autocert_json_value_t *
ngx_autocert_json_array_item(ngx_autocert_json_value_t *v, ngx_uint_t idx)
{
    ngx_autocert_json_element_t  *e;

    if (v == NULL || v->type != NGX_AUTOCERT_JSON_ARRAY) {
        return NULL;
    }

    for (e = v->u.elements; e != NULL; e = e->next) {
        if (idx == 0) {
            return e->value;
        }
        idx--;
    }

    return NULL;
}


ngx_uint_t
ngx_autocert_json_array_count(ngx_autocert_json_value_t *v)
{
    ngx_autocert_json_element_t  *e;
    ngx_uint_t                    n;

    if (v == NULL || v->type != NGX_AUTOCERT_JSON_ARRAY) {
        return 0;
    }

    n = 0;
    for (e = v->u.elements; e != NULL; e = e->next) {
        n++;
    }

    return n;
}


ngx_int_t
ngx_autocert_json_number_int(ngx_autocert_json_value_t *v, ngx_int_t *out)
{
    u_char     *p, *last;
    ngx_int_t   n;

    if (v == NULL || v->type != NGX_AUTOCERT_JSON_NUMBER) {
        return NGX_ERROR;
    }

    p = v->u.number.data;
    last = p + v->u.number.len;

    /* plain non-negative integer only: no sign, '.', 'e'/'E' */
    if (p >= last) {
        return NGX_ERROR;
    }

    n = 0;
    while (p < last) {
        if (*p < '0' || *p > '9') {
            return NGX_ERROR;
        }
        /* overflow guard: n*10 + d must stay <= NGX_MAX_INT_T_VALUE */
        if (n > (NGX_MAX_INT_T_VALUE - (*p - '0')) / 10) {
            return NGX_ERROR;
        }
        n = n * 10 + (*p - '0');
        p++;
    }

    *out = n;
    return NGX_OK;
}
