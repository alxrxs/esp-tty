# test/stubs/ -- Native Test Stubs

The `[env:native]` PlatformIO environment compiles and runs unit tests on the
host (Linux or macOS) without ESP-IDF, FreeRTOS, wolfSSH, wolfCrypt, or mbedtls
installed as system libraries. The production library code under `lib/` includes
headers from all of those frameworks, so the native build needs something on the
include path that satisfies the preprocessor. The stubs in this directory fill
that role. They are header-only (every function is a `static inline`) so they
produce no object file of their own and carry no link-time overhead beyond the
OpenSSL `-lcrypto` already required. They are never compiled into firmware
builds; the `test/stubs/` path appears only in the `build_flags` of
`[env:native]` in `platformio.ini`.

Two include paths are added in `platformio.ini`'s `[env:native]` section:
`-I test/stubs` and `-I test/stubs/wolfssl`. The first puts `esp_err.h`,
`esp_log.h`, and the `freertos/` and `mbedtls/` subdirectories on the standard
search path, so `#include "esp_err.h"` and `#include "mbedtls/sha256.h"` both
resolve. The second adds the wolfCrypt stub directory itself to the path, so
`#include "wolfssl/wolfcrypt/sha256.h"` resolves from the `wolfssl/` subtree
while also allowing `wolfcrypt/settings.h` to be reached without a prefix from
within the stub headers that include each other. The `extra_scripts` line in the
same `[env:native]` section points at `test/scripts/native_link_openssl.py`,
which appends `-lcrypto` to the link step. That single flag is sufficient because
every stub that calls an OpenSSL function includes the relevant OpenSSL header
directly, so the linker can resolve all symbols from the system `libcrypto.so`.

The wolfCrypt stubs under `wolfssl/wolfcrypt/` serve the code in
`lib/pubkey_auth/`. The `settings.h` stub defines just two type aliases (`byte`
for `unsigned char` and `word32` for `unsigned int`) so that the real wolfCrypt
type system compiles without any platform-detection macros. The `sha256.h` stub
maps the wolfCrypt streaming SHA-256 API (`wc_InitSha256`, `wc_Sha256Update`,
`wc_Sha256Final`) to the OpenSSL 3 `EVP_MD_CTX` interface; `pubkey_auth.c` calls
these when computing the SHA-256 fingerprint of an authorized public key blob.
The `coding.h` stub provides `Base64_Decode`, backed by OpenSSL's
`EVP_DecodeUpdate`/`EVP_DecodeFinal` pair, and mirrors wolfCrypt's buffer-overflow
semantics by returning `BUFFER_E` when the decoded output exceeds the
caller-supplied capacity.

The mbedtls stubs under `mbedtls/` serve the code in `lib/ota_verify/`. The
`sha256.h` stub maps the mbedtls 3.x context-based SHA-256 API to the same
OpenSSL EVP interface used by the wolfCrypt SHA-256 stub. The `gcm.h` stub wraps
`EVP_aes_256_gcm()` to implement the mbedtls AES-256-GCM streaming API
(`mbedtls_gcm_starts`, `mbedtls_gcm_update`, `mbedtls_gcm_finish`); it also
exposes a non-standard helper `mbedtls_gcm_set_expected_tag` to work around
OpenSSL 3's restriction on extracting the GCM authentication tag after
`EVP_DecryptFinal_ex`, enabling `ota_verify.c`'s constant-time tag comparison
to behave correctly under `OTA_VERIFY_NATIVE_TEST`. The ECDSA stubs span three
headers: `ecp.h` defines `mbedtls_mpi` (backed by `BIGNUM`) and
`mbedtls_ecp_point` / `mbedtls_ecp_keypair` (backed by `EC_KEY`); `pk.h`
implements `mbedtls_pk_parse_public_key` using `PEM_read_bio_PUBKEY` and
`EVP_PKEY_get1_EC_KEY`; and `ecdsa.h` implements `mbedtls_ecdsa_verify` by
constructing an `ECDSA_SIG` from the raw `r`/`s` MPIs and calling
`ECDSA_do_verify`. The `error.h` stub is an empty header; mbedtls error strings
are not needed in test output. The two ESP-IDF stubs at the root of `test/stubs/`
are similarly thin: `esp_err.h` defines the numeric `ESP_OK` / `ESP_ERR_*`
constants and an `ESP_ERROR_CHECK` macro that calls `abort()` on failure, while
`esp_log.h` maps the five log macros to `fprintf(stdout/stderr, ...)`.

The FreeRTOS stub is the simplest of all: `freertos/FreeRTOS.h` defines only
`TickType_t`, `pdMS_TO_TICKS`, and `portMAX_DELAY`. No task, queue, or
semaphore APIs are stubbed because the libraries under test do not call the
FreeRTOS scheduler directly; the stub exists only to satisfy transitive
`#include <freertos/FreeRTOS.h>` directives that appear in headers pulled in by
library code at compile time.

## Subdir summary

| Path | What it stubs | Backed by |
|---|---|---|
| `freertos/FreeRTOS.h` | `TickType_t`, `pdMS_TO_TICKS`, `portMAX_DELAY` | Plain C typedefs and macros |
| `mbedtls/error.h` | mbedtls error-string API | No-op (empty header) |
| `mbedtls/sha256.h` | `mbedtls_sha256_init/starts/update/finish/free` | OpenSSL `EVP_MD_CTX` + `EVP_sha256()` |
| `mbedtls/gcm.h` | `mbedtls_gcm_init/setkey/starts/update/finish/free` | OpenSSL `EVP_CIPHER_CTX` + `EVP_aes_256_gcm()` |
| `mbedtls/ecp.h` | `mbedtls_mpi`, `mbedtls_ecp_point/group/keypair` types and init/free | OpenSSL `BIGNUM` and `EC_KEY` |
| `mbedtls/pk.h` | `mbedtls_pk_context`, `mbedtls_pk_parse_public_key`, `mbedtls_pk_ec` | OpenSSL `PEM_read_bio_PUBKEY`, `EVP_PKEY_get1_EC_KEY` |
| `mbedtls/ecdsa.h` | `mbedtls_ecdsa_context`, `mbedtls_ecdsa_from_keypair`, `mbedtls_ecdsa_verify` | OpenSSL `ECDSA_SIG`, `ECDSA_do_verify` |
| `wolfssl/wolfcrypt/settings.h` | `byte` and `word32` type aliases | Plain C typedefs |
| `wolfssl/wolfcrypt/sha256.h` | `wc_InitSha256`, `wc_Sha256Update`, `wc_Sha256Final` | OpenSSL `EVP_MD_CTX` + `EVP_sha256()` |
| `wolfssl/wolfcrypt/coding.h` | `Base64_Decode`, `BAD_FUNC_ARG`, `BUFFER_E` | OpenSSL `EVP_DecodeUpdate`/`EVP_DecodeFinal` |
| `esp_err.h` | `esp_err_t`, `ESP_OK`, `ESP_ERR_*`, `ESP_ERROR_CHECK` | Integer constants + abort macro |
| `esp_log.h` | `ESP_LOGI`, `ESP_LOGW`, `ESP_LOGE`, `ESP_LOGD`, `ESP_LOGV` | `fprintf` to stdout/stderr |
