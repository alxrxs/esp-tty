# lib/ -- Platform-Agnostic Component Libraries

This directory holds the C libraries that are shared between the ESP32-S3
firmware and the native host test suite.  Most are a single `.c`/`.h` pair
with no compile-time dependency on FreeRTOS, wolfSSH, or ESP-IDF headers
except where those dependencies are guarded by an `#ifdef`.  The same source
files compile for both the on-device PlatformIO target (`env:esp32s3`) and the
native Linux host target (`env:native`), which runs the full Unity test suite
via `pio test -e native` without hardware or an ESP-IDF toolchain.

## Dual-build pattern

On the ESP32-S3 target each library uses the native ESP-IDF and FreeRTOS
primitives: FreeRTOS `xStreamBufferCreateWithCaps` with `MALLOC_CAP_SPIRAM`
for blocking I/O, mbedTLS for cryptographic operations, ESP-IDF NVS for
persistent storage, and `esp_ota_ops.h` for OTA flash management.

On the native host the same source files are recompiled with a small set of
preprocessor flags and stub headers supplied from `test/stubs/`.  The flags
and stubs are declared in the `[env:native]` section of `platformio.ini`:

- `RING_NATIVE=1` -- selects the POSIX `pthread_mutex_t` / `pthread_cond_t`
  backend in `lib/ring/ring.c` and the `pthread_mutex_t`-backed path in
  `lib/scrollback/scrollback.c`.
- `UNIT_TEST` -- selects the native circular-buffer struct layout in
  `lib/scrollback/scrollback.c`.
- `CRED_STORE_NATIVE_TEST` -- replaces the ESP-IDF NVS calls in
  `lib/cred_store/cred_store.c` with an in-memory backend so the parse +
  load/save logic can run natively.
- `ROLLBACK_DECISION_NATIVE_TEST` -- inlines a minimal `esp_ota_img_states_t`
  enum stub so `lib/rollback_decision/rollback_decision.c` builds without any
  ESP-IDF header.

Crypto stubs live in `test/stubs/wolfssl/wolfcrypt/` (OpenSSL-backed shims
for the wolfCrypt SHA-256, base64, RNG, RSA, ECC, ASN, and PKCS#7 surfaces
that the firmware uses outside SCEP). Libraries that drive mbedTLS
directly (`scep_proto`, `cred_store`) include the real mbedTLS headers and
link against the host's system `libmbedcrypto` / `libmbedx509` / `libmbedtls`
via `test/scripts/native_link_openssl.py`. Libraries that have no platform
dependencies -- `bridge`, `term_resize`, `rollback_decision`, `wifi_state`,
`cert_renewer/cert_renewer_decide` -- compile on the host without any stubs
at all.

## Libraries

| Library | One-line description | Native test suite |
|---|---|---|
| [bridge](bridge/) | Pure byte-pump; copies data between an abstract read callback and an abstract write callback until a stop flag is set | `test/native/test_bridge/` |
| [cert_renewer](cert_renewer/) | Pure decision function: given current time, stored cert NotAfter, and renewal window, returns SKIP_NO_CLOCK / SKIP_VALID / RENEW_NOW | `test/native/test_cert_renewer/` |
| [cred_store](cred_store/) | NVS-encrypted store for the SCEP-enrolled device key + cert + CA chain + NotAfter epoch; mbedtls-based NotAfter/NotBefore parsing | `test/native/test_cred_store/`, `test/native/test_cred_store_integration/` |
| [mdns_dispatch](mdns_dispatch/) | mDNS service registration dispatcher with task-create retry policy | `test/native/test_mdns_dispatch/` |
| [pubkey_auth](pubkey_auth/) | OpenSSH authorized-key parser, SHA-256 fingerprint hasher, constant-time auth check, and username router | `test/native/test_pubkey_auth/`, `test/native/test_auth_check/`, `test/native/test_user_class/`, `test/native/test_host_key/` |
| [ring](ring/) | Blocking single-producer/single-reader byte queue; FreeRTOS StreamBuffer on device, POSIX condvar on native | `test/native/test_ring/` |
| [rollback_decision](rollback_decision/) | Single pure function mapping an OTA partition state to mark-valid or no-op | `test/native/test_rollback_decision/` |
| [scep_proto](scep_proto/) | RFC 8894 SCEP wire-protocol primitives: PKCS#10 CSR with challengePassword, PKCS#7 SignedData(EnvelopedData(CSR)) PKCSReq, GetCACert + CertRep parsing. Built on mbedTLS ASN.1 writers + RSA + AES + X.509 | `test/native/test_scep_proto/`, `test/embedded/test_scep_proto_smoke/` |
| [scep_transport](scep_transport/) | HTTPS GET/POST wrapper around `esp_http_client` for the SCEP `GetCACert` and `PKIOperation` endpoints; embedded TLS trust anchor in `main/certs/scep_ca.pem` | on-device only |
| [scrollback](scrollback/) | Circular capture buffer that records USB CDC output between SSH sessions and replays recent lines on reconnect | `test/native/test_scrollback/` |
| [ssh_keepalive](ssh_keepalive/) | SSH-protocol-level keepalive: tracks idle time, dispatches `keepalive@openssh.com`, drops the session after N misses | `test/native/test_ssh_keepalive/` |
| [term_resize](term_resize/) | Formats the xterm `\033[8;<rows>;<cols>t` CSI sequence for injection into the USB-bound ring on SSH window-change events | `test/native/test_term_resize/` |
| [usb_cdc_drain](usb_cdc_drain/) | TinyUSB CDC RX drain loop; reads the FIFO to exhaustion 64 bytes at a time, forwarding to the ring and scrollback buffer | `test/native/test_cdc_drain/` |
| [wifi_state](wifi_state/) | Pure decision function for the bootstrap-PSK ↔ WPA3-Enterprise state machine: given cert / clock / retry-count state, returns ENTERPRISE / BOOTSTRAP_NTP_ONLY / BOOTSTRAP_FULL | `test/native/test_wifi_state/` |

## Further reading

Most subdirectories contain their own README with the full API, concurrency
contracts, image formats, error codes, and a description of every test case.
The top-level [README.md](../README.md) describes the overall firmware
architecture, hardware requirements, and build instructions.
