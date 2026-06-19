/*
 * ngx_autocert_json — minimal JSON reader for ACME responses (M4c).
 *
 * ACME servers return small, well-formed JSON (RFC 8259) documents: the
 * directory, account, order, authorization and challenge objects. This is a
 * tiny recursive-descent parser that turns one such document into a value tree
 * allocated entirely from a caller-owned ngx_pool_t, plus a handful of typed
 * accessors. It is deliberately NOT a general-purpose JSON library — just
 * enough to walk the objects the ACME state machine (M4d+) needs.
 *
 * Even though the response arrives over a verified-TLS channel, the bytes are
 * parsed defensively: bounded nesting depth, no reliance on NUL termination
 * (the input is an ngx_str_t length-delimited buffer, e.g. M4b's
 * req->body_out), strict token validation, and overflow-guarded number/length
 * handling. Malformed input yields NGX_ERROR, never a crash or read past the
 * end.
 *
 * Scope of the JSON it must handle:
 *   - objects with string keys
 *   - string values (with \" \\ \/ \b \f \n \r \t and \uXXXX escapes, incl.
 *     surrogate pairs, decoded to UTF-8)
 *   - arrays
 *   - the literals true / false / null
 *   - numbers (parsed but kept as their raw text; ACME rarely needs them and a
 *     few are large — callers that want an integer use _number_int)
 *
 * No nginx HTTP dependency — only <ngx_core.h> — so it unit-tests against
 * canned ACME vectors outside a running server, like the M3 crypto TU.
 */

#ifndef _NGX_AUTOCERT_JSON_H_INCLUDED_
#define _NGX_AUTOCERT_JSON_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef enum {
    NGX_AUTOCERT_JSON_NULL = 0,
    NGX_AUTOCERT_JSON_BOOL,
    NGX_AUTOCERT_JSON_NUMBER,
    NGX_AUTOCERT_JSON_STRING,
    NGX_AUTOCERT_JSON_ARRAY,
    NGX_AUTOCERT_JSON_OBJECT
} ngx_autocert_json_type_e;


typedef struct ngx_autocert_json_value_s  ngx_autocert_json_value_t;

/* One "key": value member of an object (singly linked, source order). */
typedef struct ngx_autocert_json_member_s  ngx_autocert_json_member_t;

struct ngx_autocert_json_member_s {
    ngx_str_t                     name;     /* decoded key */
    ngx_autocert_json_value_t    *value;
    ngx_autocert_json_member_t   *next;
};

/* One array element (singly linked, source order). */
typedef struct ngx_autocert_json_element_s  ngx_autocert_json_element_t;

struct ngx_autocert_json_element_s {
    ngx_autocert_json_value_t    *value;
    ngx_autocert_json_element_t  *next;
};

struct ngx_autocert_json_value_s {
    ngx_autocert_json_type_e      type;

    union {
        ngx_uint_t                    boolean;   /* BOOL: 0/1 */
        ngx_str_t                     string;    /* STRING: decoded bytes; may
                                                  * contain an interior NUL
                                                  * (from a \u0000 escape) -
                                                  * always use .len, never treat
                                                  * as a C string. */
        ngx_str_t                     number;    /* NUMBER: raw token text */
        ngx_autocert_json_member_t   *members;   /* OBJECT: NULL if empty */
        ngx_autocert_json_element_t  *elements;  /* ARRAY: NULL if empty */
    } u;
};


/*
 * Parse a complete JSON document from [data, data+len). The whole input must be
 * one JSON value (optionally surrounded by whitespace); trailing non-space
 * bytes are an error. Returns the root value (pool-allocated) or NULL on any
 * malformed input / depth-limit / OOM. Never reads past data+len.
 */
ngx_autocert_json_value_t *ngx_autocert_json_parse(ngx_pool_t *pool,
    u_char *data, size_t len);


/*
 * Look up a member by key in an OBJECT value. Returns the value, or NULL if v
 * is not an object or the key is absent. Key match is exact (case-sensitive),
 * as ACME member names are. On a duplicate key the FIRST occurrence (source
 * order) wins — RFC 8259 leaves duplicates undefined; ACME never sends them.
 */
ngx_autocert_json_value_t *ngx_autocert_json_object_get(
    ngx_autocert_json_value_t *v, const char *key);


/*
 * Convenience: the string value of object member `key`, into *out. Returns
 * NGX_OK only if the member exists AND is a JSON string; NGX_DECLINED if the
 * member is absent; NGX_ERROR if present but not a string. *out aliases the
 * pool-allocated decoded bytes (do not free).
 */
ngx_int_t ngx_autocert_json_object_str(ngx_autocert_json_value_t *v,
    const char *key, ngx_str_t *out);


/*
 * Iterate array elements. Pass idx starting at 0; returns the element value or
 * NULL when idx is out of range / v is not an array. O(idx) per call (linked
 * list) — fine for the short ACME arrays. _array_count returns the length (0
 * for a non-array).
 */
ngx_autocert_json_value_t *ngx_autocert_json_array_item(
    ngx_autocert_json_value_t *v, ngx_uint_t idx);
ngx_uint_t ngx_autocert_json_array_count(ngx_autocert_json_value_t *v);


/*
 * Parse a NUMBER value as a non-negative integer into *out. Returns NGX_OK on a
 * plain non-negative integer that fits in ngx_int_t, NGX_ERROR otherwise (not a
 * number, negative, fractional/exponent, or overflow). ACME uses this only for
 * a few small integers.
 */
ngx_int_t ngx_autocert_json_number_int(ngx_autocert_json_value_t *v,
    ngx_int_t *out);


#endif /* _NGX_AUTOCERT_JSON_H_INCLUDED_ */
