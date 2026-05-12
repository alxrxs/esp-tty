# lib/ — Platform-Agnostic Component Libraries

This directory holds the nine C libraries that are shared between the ESP32-S3
firmware and the native host test suite.  Each library is a single `.c`/`.h`
pair with no compile-time dependency on FreeRTOS, wolfSSH, or ESP-IDF headers
except where those dependencies are guarded by an `#ifdef`.  The same source
files compile for both the on-device PlatformIO target (`env:esp32s3`) and the
native Linux host target (`env:native`), which runs the full Unity test suite
via `pio test -e native` without hardware or an ESP-IDF toolchain.

## Dual-build pattern

On the ESP32-S3 target each library uses the native ESP-IDF and FreeRTOS
primitives: FreeRTOS `xStreamBufferCreateWithCaps` with `MALLOC_CAP_SPIRAM`
for blocking I/O, PSA Crypto / mbedtls for cryptographic operations, and
`esp_ota_ops.h` for OTA flash management.

On the native host the same source files are recompiled with a small set of
preprocessor flags and stub headers supplied from `test/stubs/`.  The flags
and stubs are declared in the `[env:native]` section of `platformio.ini`:

- `RING_NATIVE=1` — selects the POSIX `pthread_mutex_t` / `pthread_cond_t`
  backend in `lib/ring/ring.c` and the `pthread_mutex_t`-backed path in
  `lib/scrollback/scrollback.c`.
- `UNIT_TEST` — selects the native circular-buffer struct layout in
  `lib/scrollback/scrollback.c`.
- `OTA_VERIFY_NATIVE_TEST` — replaces the ESP-IDF OTA flash calls in
  `lib/ota_verify/ota_verify.c` with no-ops and switches the crypto backend
  from PSA to mbedtls.
- `ROLLBACK_DECISION_NATIVE_TEST` — inlines a minimal `esp_ota_img_states_t`
  enum stub so `lib/rollback_decision/rollback_decision.c` builds without any
  ESP-IDF header.

Crypto stubs live in `test/stubs/wolfssl/wolfcrypt/sha256.h` (wolfCrypt SHA-256
backed by OpenSSL 3 EVP) and `test/stubs/mbedtls/` (mbedtls 4.x AES-GCM and
ECDSA-P256 backed by OpenSSL 3 EVP).  The native build links against OpenSSL
via `test/scripts/native_link_openssl.py`.  Libraries that have no platform
dependencies — `bridge`, `term_resize`, `ota_stream`, and `rollback_decision`
— compile on the host without any stubs at all.

## Libraries

| Library | One-line description | Native test suite |
|---|---|---|
| [bridge](bridge/) | Pure byte-pump; copies data between an abstract read callback and an abstract write callback until a stop flag is set | `test/native/test_bridge/` |
| [ota_stream](ota_stream/) | Streaming read accumulator; grows a PSRAM-backed buffer geometrically until the read source closes | `test/native/test_ota_stream/` |
| [ota_verify](ota_verify/) | Streaming OTA image verifier; enforces ECDSA-P256 signature and AES-256-GCM tag before switching the boot partition | `test/native/test_ota_verify/` |
| [pubkey_auth](pubkey_auth/) | OpenSSH authorized-key parser, SHA-256 fingerprint hasher, constant-time auth check, and username router | `test/native/test_pubkey_auth/`, `test/native/test_auth_check/`, `test/native/test_user_class/`, `test/native/test_host_key/` |
| [ring](ring/) | Blocking single-producer/single-reader byte queue; FreeRTOS StreamBuffer on device, POSIX condvar on native | `test/native/test_ring/` |
| [rollback_decision](rollback_decision/) | Single pure function mapping an OTA partition state to mark-valid or no-op | `test/native/test_rollback_decision/` |
| [scrollback](scrollback/) | Circular capture buffer that records USB CDC output between SSH sessions and replays recent lines on reconnect | `test/native/test_scrollback/` |
| [term_resize](term_resize/) | Formats the xterm `\033[8;<rows>;<cols>t` CSI sequence for injection into the USB-bound ring on SSH window-change events | `test/native/test_term_resize/` |
| [usb_cdc_drain](usb_cdc_drain/) | TinyUSB CDC RX drain loop; reads the FIFO to exhaustion 64 bytes at a time, forwarding to the ring and scrollback buffer | `test/native/test_cdc_drain/` |

## Further reading

Each subdirectory contains its own README with the full API, concurrency
contracts, image formats, error codes, and a description of every test case.
The top-level [README.md](../README.md) describes the overall firmware
architecture, hardware requirements, and build instructions.
