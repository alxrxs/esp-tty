# lib/ota_verify -- streaming OTA image verifier and decryptor

This module authenticates and decrypts OTA firmware images before writing them
to flash. It consumes the binary format produced by `scripts/sign_firmware.py`
and enforces two independent cryptographic gates before the new firmware is
selected as the boot partition. Neither gate alone is sufficient: a valid
signature with a wrong AES key is rejected, and a valid AES-GCM tag with a
forged signature is rejected. Only when both pass does the module call
`esp_ota_set_boot_partition()`.

## Image format

Images are produced by `scripts/sign_firmware.py`, which takes a raw
`firmware.bin`, an ECDSA-P256 private key in PEM format, and a 32-byte raw
AES-256 key. The resulting `.ota` file has the following layout:

```
Offset  Size  Field
------  ----  -----
     0     8  magic "ESPOTA1\0"
     8     4  version (LE uint32, currently 1)
    12     4  plaintext_len (LE uint32, original firmware size in bytes)
    16    12  AES-256-GCM IV (12 random bytes)
    28    16  AES-256-GCM authentication tag
    44     N  ciphertext (AES-256-GCM encrypted firmware, same length as plaintext)
  44+N    64  ECDSA-P256 signature, raw r||s (32 + 32 bytes)
```

The signed region covers bytes 0 through 43+N inclusive (magic, version,
plaintext_len, IV, tag, and ciphertext). The 64-byte trailing signature is
explicitly excluded from the signed region so that it can be extracted from the
stream without re-hashing. The script computes `SHA-256(header || ciphertext)`
and signs the resulting 32-byte digest using `ECDSA(Prehashed(SHA-256))` from
the `cryptography` Python package. The script self-tests its own output before
returning, re-parsing the written file and re-verifying the signature.

## Streaming verify API

The public interface (`ota_verify.h`) is a three-function streaming API:

- `ota_verify_begin(pub_key_pem, pub_key_pem_len, aes_key)` -- allocate and
  initialise a heap-resident `ota_verify_ctx_t`. Imports the AES-256 and
  ECDSA-P256 public keys into the PSA Crypto keystore on device, or into the
  mbedtls context on the native build. Returns `NULL` on allocation failure or
  if the key material is malformed.
- `ota_verify_feed(ctx, data, len, total_image_len)` -- feed the next contiguous
  chunk of the image, in order from byte 0. The first call establishes the total
  image size and validates it is at least `OTA_HEADER_SIZE + OTA_SIG_LEN` bytes.
  Internally the function accumulates the 44-byte header on first call(s), then
  opens an ESP-IDF OTA write handle and begins streaming ciphertext through
  `psa_aead_update` into the inactive OTA partition while simultaneously
  updating the SHA-256 hash of the signed region. A 64-byte lookahead tail
  buffer ensures the trailing signature bytes are never passed to the decryptor
  or hasher. The header is hashed in full before any ciphertext bytes are
  processed. Ciphertext hash and decrypt operations are chunked to 4096 bytes to
  stay within the ESP32-S3 internal SRAM budget.
- `ota_verify_end(ctx)` -- finalise the session. First checks that the number of
  ciphertext bytes received matches `plaintext_len` from the header
  (`OTA_VERIFY_ERR_LENGTH_MISMATCH` if not). Then verifies the ECDSA-P256
  signature via `psa_verify_hash` (gate 1). Then calls `psa_aead_verify` to
  finalise the GCM decryption and authenticate the tag atomically (gate 2). Only
  if both gates pass does the function call `esp_ota_end` and
  `esp_ota_set_boot_partition`. On any failure it calls `esp_ota_abort` and
  returns the relevant error code; the boot partition is never changed. Frees the
  context in all paths.
- `ota_verify_abort(ctx)` -- safe teardown for mid-stream cancellation. If the
  header was already parsed (i.e. a flash write handle was opened), it calls
  `esp_ota_abort` to discard the partial write. Safe to call with `NULL`.

In `main/ota_session.c`, the "ota" SSH username triggers `ota_session_handler`,
which calls `ota_verify_begin` with key material embedded at build time
(`_binary_sign_pub_pem_start`, `_binary_aes_key_start`), reads the full image
into a PSRAM-backed buffer via `ota_stream_read_all`, calls `ota_verify_feed`
once with the complete buffer, then calls `ota_verify_end`. On success it sends
`OTA_OK\n` to the SSH client and schedules `esp_restart()` after 2 seconds. On
any failure it sends an `OTA_ERR: <message>\n` reply and returns without
rebooting.

## Dual native and target build

On the ESP32-S3 target the module uses the PSA Crypto API (`psa/crypto.h`) with
`psa_hash_*` for SHA-256 (hardware-accelerated), `psa_aead_*` for AES-256-GCM,
and `psa_verify_hash` for ECDSA-P256. PEM public keys are parsed by a
self-contained base64 decoder and a fixed-offset SubjectPublicKeyInfo DER parser
(the P-256 DER encoding is a fixed 91-byte structure; the parser anchors on
known byte offsets and rejects any DER that is not exactly 91 bytes). Flash
writes go through `esp_ota_write` from `esp_ota_ops.h`.

When compiled with `OTA_VERIFY_NATIVE_TEST` defined, all ESP-IDF OTA calls
(`esp_ota_begin`, `esp_ota_write`, `esp_ota_end`, `esp_ota_abort`,
`esp_ota_set_boot_partition`) are replaced with inline no-ops. The crypto
backend switches from PSA to mbedtls 4.x with OpenSSL 3 EVP stubs from
`test/stubs/mbedtls/`. The logging macros map to `fprintf(stderr/stdout)`.
This lets the full verify pipeline run on a Linux CI host without any hardware
or ESP-IDF installation.

## Error codes and tested edge cases

`ota_verify_err_t` has eleven values, each with a human-readable string from
`ota_verify_strerror`:

| Code | Meaning |
|------|---------|
| `OTA_VERIFY_OK` | Success |
| `OTA_VERIFY_ERR_MAGIC` | First 8 bytes do not match `"ESPOTA1\0"` |
| `OTA_VERIFY_ERR_VERSION` | Version field is not 1 |
| `OTA_VERIFY_ERR_TRUNCATED` | Image shorter than `OTA_HEADER_SIZE + OTA_SIG_LEN`, or `ota_verify_end` called before enough bytes were fed |
| `OTA_VERIFY_ERR_SIG` | ECDSA-P256 signature verification failed |
| `OTA_VERIFY_ERR_TAG` | AES-GCM authentication tag mismatch |
| `OTA_VERIFY_ERR_FLASH` | `esp_ota_begin`, `esp_ota_write`, `esp_ota_end`, or `esp_ota_set_boot_partition` returned an error |
| `OTA_VERIFY_ERR_OOM` | `calloc` returned `NULL` in `ota_verify_begin` |
| `OTA_VERIFY_ERR_CRYPTO` | mbedtls or PSA internal error |
| `OTA_VERIFY_ERR_PARAM` | `NULL` context or key pointer passed to an API function |
| `OTA_VERIFY_ERR_LENGTH_MISMATCH` | Ciphertext bytes received does not equal `plaintext_len` from header |
| `OTA_VERIFY_ERR_EMPTY_IMAGE` | `plaintext_len == 0`; flashing a zero-byte image would brick the device |

The 20 native test cases in `test/native/test_ota_verify/test_ota_verify.c`
cover: the golden vector in one shot, the golden vector in 1-byte and 13-byte
chunks (exercises the tail-buffer boundary at every alignment), a flipped
ciphertext byte (ECDSA fails), a flipped signature byte (ECDSA fails), wrong
magic, truncated header fed then `end` called early, `total_image_len` below the
minimum, wrong AES key (ECDSA passes because ciphertext is unchanged, GCM tag
then fails), `NULL` public key or AES key to `ota_verify_begin`, `strerror`
coverage, wrong version field, `plaintext_len` mismatch, `abort` before header
is parsed, `abort(NULL)` as a no-op, `feed(NULL, ...)` returning
`OTA_VERIFY_ERR_PARAM`, empty image (`plaintext_len == 0`), `strerror` for the
empty-image code, and a truncated PEM body that decodes to fewer than 91 DER
bytes (rejected by `ota_verify_begin`).
