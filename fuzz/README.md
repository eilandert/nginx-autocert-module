# Fuzzing

`fuzz_json` exercises `ngx_autocert_json_parse()` with libFuzzer, ASan and
UBSan. The target links the shipped parser source against the same small nginx
core object set used by `test/test_json.c`.

```bash
# Build a configured nginx tree first, then:
NGX_BUILD_DIR=/path/to/nginx-1.xx.x bash fuzz/build.sh
./fuzz/fuzz_json -max_total_time=120 fuzz/corpus/
```
