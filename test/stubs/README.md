# test/stubs/ -- Native Test Stubs

The `[env:native]` PlatformIO environment compiles and runs the unit tests
on the host without ESP-IDF, FreeRTOS, wolfSSH, or wolfCrypt installed. The
production library code under `lib/` includes headers from those
frameworks, so the native build needs something on the include path that
satisfies the preprocessor. The stubs in this directory fill that role.
Every stub is header-only (each function is a `static inline`), so the
stubs produce no object file and add no link-time overhead beyond the
host's `-lcrypto` and the system mbedTLS libraries already required by
SCEP / cred_store tests. They are never compiled into firmware builds; the
`test/stubs/` paths appear only in the `[env:native]` `build_flags` in
`platformio.ini`.

Two include paths are added in `[env:native]`: `-I test/stubs` and
`-I test/stubs/wolfssl`. The first puts the ESP-IDF stubs (`esp_err.h`,
`esp_log.h`, `esp_http_client.h`, `esp_heap_caps.h`) and the `freertos/`
subdirectory on the search path. The `mbedtls/` directory is empty: SCEP
and cred_store tests include the real mbedTLS headers from the host's
system install and link against `libmbedcrypto` / `libmbedx509` /
`libmbedtls` via `test/scripts/native_link_openssl.py`. The second include
path lets `#include "wolfssl/wolfcrypt/sha256.h"` (etc.) resolve from the
wolfCrypt shim subtree while also letting the shim headers `#include
"wolfcrypt/settings.h"` reach each other without a prefix.

## File index

### Root (ESP-IDF + bare-platform stubs)

| File | What it stubs | Backed by |
|---|---|---|
| `esp_err.h` | `esp_err_t`, `ESP_OK`, `ESP_ERR_*` constants, `ESP_ERROR_CHECK` macro | Integer constants + `abort()` macro |
| `esp_log.h` | `ESP_LOGE`, `ESP_LOGW`, `ESP_LOGI`, `ESP_LOGD`, `ESP_LOGV` | `fprintf` to stdout/stderr |
| `esp_heap_caps.h` | `heap_caps_malloc`, `heap_caps_free`, the `MALLOC_CAP_*` flag set | Plain `malloc` / `free` |
| `esp_http_client.h` | `esp_http_client_*` API surface used by `lib/scep_transport/` | Test-controlled in-memory request/response captured by `test_scep_transport` |

### `freertos/`

| File | What it stubs | Backed by |
|---|---|---|
| `FreeRTOS.h` | `TickType_t`, `pdMS_TO_TICKS`, `portMAX_DELAY` | Plain typedefs and `#define` macros |

No task / queue / semaphore APIs are stubbed because the libraries under
test do not call the FreeRTOS scheduler directly; the stub exists only to
satisfy transitive `#include <freertos/FreeRTOS.h>` directives that appear
in headers pulled in by production code.

### `mbedtls/`

Empty. `lib/scep_proto/` and `lib/cred_store/` include the real mbedTLS
headers and link against the host's system mbedTLS at test time.

### `wolfssl/wolfcrypt/`

OpenSSL-backed shim headers that let production code which includes the
wolfCrypt headers (`pubkey_auth`, `host_key`, `ota_session` stand-ins)
compile and run on the host. The shims map the wolfCrypt API to OpenSSL 3
EVP calls and mirror wolfCrypt's error-code conventions (`BAD_FUNC_ARG`,
`BUFFER_E`, etc.) where the production code inspects them.

| File | What it stubs | Backed by |
|---|---|---|
| `settings.h` | `byte`, `word32` type aliases | Plain typedefs |
| `types.h` | Auxiliary integer typedefs used by wolfCrypt headers | Plain typedefs |
| `error-crypt.h` | wolfCrypt error-code constants | `#define` macros |
| `sha256.h` | `wc_InitSha256`, `wc_Sha256Update`, `wc_Sha256Final` | OpenSSL `EVP_MD_CTX` + `EVP_sha256()` |
| `coding.h` | `Base64_Decode`, plus `BAD_FUNC_ARG` / `BUFFER_E` | OpenSSL `EVP_DecodeUpdate` / `EVP_DecodeFinal` |
| `random.h` | `WC_RNG`, `wc_InitRng`, `wc_RNG_GenerateBlock` | OpenSSL `RAND_bytes` |
| `rsa.h` | `RsaKey` opaque + decode / public-key extraction helpers | OpenSSL `EVP_PKEY` / `RSA` |
| `ecc.h` | `ecc_key` opaque + curve / point helpers | OpenSSL `EC_KEY` |
| `asn_public.h` | DER decode helpers (subject, validity, public key) used by `cred_store` | OpenSSL `d2i_X509` |
| `pkcs7.h` | Type and constant declarations referenced by transitive wolfCrypt header includes | Compile-only -- no function bodies; the production SCEP code uses mbedTLS, not wolfCrypt PKCS#7 |
