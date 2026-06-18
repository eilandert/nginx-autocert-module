# Continuous integration

The CI pipeline is intentionally split by feedback speed and failure class:

| Workflow | Required check | Coverage |
|---|---|---|
| `build-test.yml` | `Validation` | shell syntax, ShellCheck, cppcheck, whitespace, workflow lint |
| `build-test.yml` | `Build & load` | latest mainline nginx build, module load, config rejection, no-network serve/lifecycle tests |
| `build-test.yml` | `Compile-only` | latest Angie API compile drift guard |
| `build-test.yml` | `Crypto unit tests` | JOSE, JWK, thumbprint, JWS signing |
| `build-test.yml` | `JSON parser unit tests` | ACME JSON parser happy paths and malformed-input rejection |
| `build-test.yml` | ACME e2e jobs | Pebble account/order/issuance/renewal/backoff/rate-limit flows |
| `valgrind.yml` | `Memcheck` | unit tests and module-load checks under Valgrind |
| `codeql.yml` | `Analyze C` | CodeQL security-extended C/C++ queries |
| `security-scanners.yml` | `Secure` | flawfinder gate plus clang-tidy and Semgrep reports |
| `fuzzing.yml` | scheduled | monthly libFuzzer run of the ACME JSON parser |

All third-party actions are pinned to immutable commit SHAs. Workflows use
read-only repository permissions except CodeQL/SARIF upload jobs, which also
receive `security-events: write`.

## Local validation

```bash
bash -n tests/*.sh
shellcheck tests/*.sh
cppcheck \
  --enable=warning,performance,portability \
  --error-exitcode=1 \
  --suppress=missingIncludeSystem \
  --suppress=normalCheckLevelMaxBranches \
  --suppress=unusedFunction \
  src/*.c
git diff --check
```
