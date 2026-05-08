# test/stubs/ — Native Test Stubs

```
test/stubs/
  wolfssl/
    wolfcrypt/
      coding.h      Base64 encode/decode (OpenSSL BIO-backed)
      settings.h    Minimal wolfCrypt type aliases (byte, word32)
      sha256.h      wc_InitSha256 / wc_Sha256Update / wc_Sha256Final (EVP-backed)
  mbedtls/
    ecdsa.h         mbedtls_ecdsa_* stubs (OpenSSL EC-backed)
    ecp.h           mbedtls_ecp_* type stubs
    error.h         mbedtls_strerror stub
    gcm.h           mbedtls_gcm_* (OpenSSL EVP AEAD-backed)
    pk.h            mbedtls_pk_parse_public_key (OpenSSL PEM-backed)
    sha256.h        mbedtls_sha256_* (OpenSSL EVP-backed)
  esp_err.h         ESP_OK / ESP_ERR_* constant stubs
  esp_log.h         ESP_LOGI/W/E → fprintf stubs
  freertos/         FreeRTOS type stubs (TaskHandle_t, etc.)
  sdkconfig.h       Empty sdkconfig for native builds
```

## Why stubs are needed

Native tests (the `native` PlatformIO environment) compile and run on the host
(Linux/macOS) without ESP-IDF, wolfSSL, or mbedtls installed as libraries. The
libraries under test (`lib/pubkey_auth`, `lib/ota_verify`) call into wolfCrypt
and mbedtls APIs at the C level. To keep the native test binary self-contained
and avoid cross-compilation, stub headers implement those APIs using OpenSSL 3
(`-lcrypto`), which is available on any development machine.

The stubs are header-only (inline functions in `.h` files). They are not linked
into firmware builds; the include path for `test/stubs/` is added only in the
`[env:native]` section of `platformio.ini`.

## wolfCrypt stubs (`test/stubs/wolfssl/wolfcrypt/`)

### settings.h

Defines the minimum wolfCrypt type aliases needed by `pubkey_auth.c`:
`byte` (uint8_t) and `word32` (uint32_t). No wolfSSL feature flags are set;
crypto is handled entirely by the EVP stubs below.

### sha256.h

Maps wolfCrypt SHA-256 to OpenSSL 3 EVP:

```
wc_InitSha256(s)          →  EVP_MD_CTX_new() + EVP_DigestInit_ex(EVP_sha256())
wc_Sha256Update(s, d, n)  →  EVP_DigestUpdate(...)
wc_Sha256Final(s, out)    →  EVP_DigestFinal_ex(...)
```

Used by `pubkey_auth.c` when computing the SHA-256 fingerprint of an authorized
public key blob.

### coding.h

Provides `Base64_Decode` backed by OpenSSL's `BIO_f_base64`. Used by
`pubkey_auth.c` when decoding the base64 blob from an OpenSSH public key line.

## mbedtls stubs (`test/stubs/mbedtls/`)

### sha256.h

Maps the mbedtls 3.x SHA-256 context API to OpenSSL 3 EVP:

```
mbedtls_sha256_init(ctx)          →  EVP_MD_CTX_new()
mbedtls_sha256_starts(ctx, 0)     →  EVP_DigestInit_ex(EVP_sha256())
mbedtls_sha256_update(ctx, d, n)  →  EVP_DigestUpdate(...)
mbedtls_sha256_finish(ctx, out)   →  EVP_DigestFinal_ex(...)
mbedtls_sha256_free(ctx)          →  EVP_MD_CTX_free(...)
```

Used by `ota_verify.c` when computing the SHA-256 digest over the signed
region of an OTA image.

### gcm.h

Maps the mbedtls AES-256-GCM API to OpenSSL `EVP_CIPHER_CTX` with
`EVP_aes_256_gcm()`. Implements the encrypt (unused in verifier) and decrypt
paths needed by `ota_verify.c` to authenticate and decrypt ciphertext.

### pk.h / ecdsa.h / ecp.h

Map the mbedtls ECDSA-P256 public key parse and verify APIs to OpenSSL EC
key parsing and ECDSA verification. Used by `ota_verify.c` when verifying the
64-byte raw `r||s` ECDSA signature appended to an OTA image.

### error.h

Provides `mbedtls_strerror` as a no-op stub (writes an empty string). Error
strings are not needed in test output; the numeric error codes are logged
directly.

## ESP-IDF and FreeRTOS stubs

- `esp_err.h` — defines `ESP_OK`, `ESP_FAIL`, and the common `ESP_ERR_*`
  constants as integer literals. Allows headers that `#include "esp_err.h"` to
  compile natively.
- `esp_log.h` — maps `ESP_LOGI`, `ESP_LOGW`, `ESP_LOGE` to `fprintf` so log
  calls in library code do not require the ESP-IDF logging subsystem.
- `freertos/` — minimal type definitions (`TaskHandle_t`, etc.) for any header
  that transitively includes FreeRTOS types.
- `sdkconfig.h` — empty file. Prevents `#include "sdkconfig.h"` from failing
  in native builds.
