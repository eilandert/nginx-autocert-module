# Fuzzing

Coverage-guided (libFuzzer) fuzzing of `ngx_autocert_json_parse()` and the
JSON accessor functions. The target is built from the SHIPPED parser source by
`extract_parser.sh` — no hand-maintained copy and no nginx build tree required.

## Target

`fuzz_json` exercises the JSON parser over arbitrary byte sequences with ASan
and UBSan. It covers:

- `ngx_autocert_json_parse()` — recursive-descent over arbitrary input
- `ngx_autocert_json_object_get()` / `ngx_autocert_json_object_str()` —
  member lookup and string extraction
- `ngx_autocert_json_array_count()` / `ngx_autocert_json_array_item()` —
  array traversal
- `ngx_autocert_json_number_int()` — integer conversion with overflow guard

Why this target: `ngx_autocert_json_parse()` reads ACME server response bodies
— bytes that arrive over a verified-TLS channel but are still attacker-
influenceable (compromised CA, hostile redirect, buggy server). A single
off-by-one in the string escape decoder, surrogate-pair branch, or
number/literal scanner would be a worker-crashing OOB read. The parser is
written defensively (bounded nesting at 32 levels, length-delimited, no NUL
reliance) but coverage-guided fuzzing catches that bug class more reliably than
the ACME integration tests.

## No copy drift

The fuzz target does **not** contain a copy of the parser. `extract_parser.sh`
strips the nginx header includes from `ngx_autocert_json.h` and
`ngx_autocert_json.c` and emits both into `generated_json.inc`, compiled
against `ngx_shim.h` instead of real nginx headers. If a signature or body
changes upstream, the next fuzz build picks it up — or fails loudly rather
than fuzz stale code.

`ngx_shim.h` supplies the minimal nginx surface the parser touches:
`ngx_pool_t` with a malloc-backed allocator, `ngx_pcalloc` / `ngx_pnalloc`,
`ngx_strlen` / `ngx_strncmp`, a stub `ngx_log_debug1` macro, and the core
types (`u_char`, `ngx_int_t`, `ngx_uint_t`, `ngx_str_t`, `NGX_OK`,
`NGX_ERROR`, `NGX_DECLINED`).

The harness allocates a buffer sized **exactly** to `size` bytes with **no**
trailing NUL, so ASAN turns any read at or past the end into an immediate
heap-buffer-overflow.

## Build & run locally

```bash
# needs clang with libFuzzer (clang >= 6) — no nginx build tree needed
CC=clang bash fuzz/build.sh          # -> fuzz/fuzz_json (ASan+UBSan+fuzzer)
cd fuzz
./fuzz_json -max_total_time=120 -print_final_stats=1 corpus/
```

The valgrind-replay path (plain compile, no sanitizers):

```bash
CC=clang CFLAGS='-g -O1' bash fuzz/build.sh
```

A crash drops a `crash-*` reproducer; re-run with `./fuzz_json crash-<id>` to
reproduce. Add the reproducer to `corpus/` (named `regress_*`) so it becomes a
permanent regression seed.

## Corpus

`corpus/` contains 10 seed inputs covering the main ACME response shapes:

| file | covers |
|---|---|
| `directory.json` | ACME directory object |
| `order.json` | order with identifiers + authorizations arrays |
| `account.json` | newAccount response |
| `authz.json` | authorization + challenges array |
| `escapes.json` | all JSON string escape types incl. surrogate pairs |
| `numbers.json` | integer, negative, float, exponent edge cases |
| `unicode.json` | UTF-8 multibyte strings in array |
| `deep_nest.json` | 9-level object nesting |
| `truncated.json` | mid-string truncation (parse error path) |
| `empty_obj.json` | minimal valid input |

## CI

`.github/workflows/fuzzing.yml` runs this monthly (1st of the month) and on
manual dispatch, mirroring the `valgrind` / `codeql` heavy-job cadence.
The per-change gate is the ASan+UBSan build-test suite in `build-test.yml`.
