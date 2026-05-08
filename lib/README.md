# lib/ — Shared Libraries

This directory contains ESP-IDF-agnostic C libraries shared between the firmware
and the native host test suite. Each library has a single .c/.h pair and no
compile-time dependency on FreeRTOS, wolfSSH, or ESP-IDF headers, except where
guarded by `#ifdef` for the on-device backend.

```
lib/
  bridge/
    bridge.c
    bridge.h
  ota_verify/
    ota_verify.c
    ota_verify.h
  pubkey_auth/
    pubkey_auth.c
    pubkey_auth.h
  ring/
    ring.c
    ring.h
  rollback_decision/
    rollback_decision.c
    rollback_decision.h
```

## ring

A blocking byte-queue used as the data conduit between the USB CDC and SSH
tasks. The API is symmetric: one writer calls `ring_send()`, one reader calls
`ring_recv()`, and a closer calls `ring_close()` to unblock both.

On-device backend: FreeRTOS `xStreamBufferCreateWithCaps` allocated in PSRAM
(8 MB OPI PSRAM on the N16R8 module). The create call uses
`MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT` so the 16 KB ring does not come from the
limited internal SRAM.

Native (test) backend: POSIX `pthread_mutex_t` + `pthread_cond_t`. The
`RING_NATIVE=1` preprocessor flag switches the implementation. The two backends
share the same header and are exercised by the same test suite, so correctness
is verified on the host without touching hardware.

There is also a non-blocking `ring_try_send()` for use from the TinyUSB CDC RX
callback, which cannot block.

Tested natively: 10 cases in `test/native/test_ring/`. Covers FIFO ordering,
wrap-around, close-unblocks-reader, and backpressure semantics.

## bridge

A pure byte-pump: `bridge_pump(read_fn, read_ctx, write_fn, write_ctx, stop)`
loops calling `read_fn` and forwarding the result to `write_fn` until `*stop`
is set or either callback returns an error. No allocations, no FreeRTOS
primitives, no network or I/O calls of its own.

In the firmware, two `bridge_pump` instances run as separate FreeRTOS tasks to
provide full-duplex flow between the wolfSSH stream and the ring buffers.

The `bridge_read_fn` / `bridge_write_fn` function pointer types are defined in
`bridge.h` and can be trivially mocked for testing.

Tested natively: 3 cases in `test/native/test_bridge/`. Covers ordering, the
stop-flag termination path, and no-drop guarantees.

## pubkey_auth

Handles OpenSSH authorized-key parsing and the wolfSSH auth callback without
linking wolfSSH itself.

The library has three responsibilities:

1. `pubkey_parse_b64` — locate the base64 blob in an OpenSSH `authorized_keys`
   line ("ssh-ed25519 AAAA... comment").
2. `pubkey_compute_hash` — base64-decode the blob and compute
   `SHA-256(uint32be(blob_len) || blob)`, producing a 32-byte fingerprint that
   is stored at startup and compared against presented keys in the auth callback.
3. `pubkey_auth_check` — constant-time comparison of the presented key hash
   against the stored hash. Returns `PUBKEY_AUTH_OK` or `PUBKEY_AUTH_REJECTED`.
4. `pubkey_classify_user` — map an SSH username to `PUBKEY_USER_DEFAULT` (normal
   session) or `PUBKEY_USER_OTA` (OTA session, username "ota"), routing the auth
   callback to the correct stored key hash.
5. `format_fingerprint` — format a 32-byte digest as colon-separated lowercase
   hex for the UART boot log.

On native builds the SHA-256 hash is backed by OpenSSL 3 EVP via the stubs in
`test/stubs/wolfssl/wolfcrypt/sha256.h`.

Tested natively: 11 cases in `test/native/test_pubkey_auth/`, 5 cases in
`test/native/test_auth_check/`, and 9 cases in `test/native/test_user_class/`.
The `format_fingerprint` helper is covered by 9 cases in
`test/native/test_host_key/`.

## ota_verify

Streaming OTA image verifier and decryptor. Consumes the binary format produced
by `scripts/sign_firmware.py`:

```
Offset  Size  Field
------  ----  -----
     0     8  magic "ESPOTA1\0"
     8     4  version (LE uint32, currently 1)
    12     4  plaintext_len (LE uint32)
    16    12  AES-256-GCM IV (12 bytes)
    28    16  AES-256-GCM authentication tag
    44     N  ciphertext
  44+N    64  ECDSA-P256 signature (raw r||s) over SHA-256(header + ciphertext)
```

The verifier API is three-step:

- `ota_verify_begin(pub_key_pem, pub_key_pem_len, aes_key)` — allocate a
  streaming context.
- `ota_verify_feed(ctx, data, len, total_image_len)` — feed the next chunk.
  Internally accumulates the header, then streams ciphertext into the inactive
  OTA flash partition via `esp_ota_write` while hashing the signed region.
- `ota_verify_end(ctx)` — verify the ECDSA signature and AES-GCM tag. On
  success, calls `esp_ota_set_boot_partition`. On any failure, calls
  `esp_ota_abort` and returns an error code without touching the boot partition.

The `ota_verify_abort(ctx)` function tears down the session if the SSH
connection drops mid-stream.

On-device: uses mbedtls (hardware-accelerated on ESP32-S3 for AES and SHA) and
the ESP-IDF OTA partition API.

Native backend: `OTA_VERIFY_NATIVE_TEST` replaces the flash write calls with
no-ops and backs the mbedtls API with OpenSSL 3 EVP stubs from
`test/stubs/mbedtls/`.

Tested natively: 20 cases in `test/native/test_ota_verify/`.

## rollback_decision

A single-function library extracted from `main.c` so the OTA rollback decision
can be unit-tested without ESP-IDF. `rollback_decide(state)` returns
`ROLLBACK_DECISION_MARK_VALID` only when `state == ESP_OTA_IMG_PENDING_VERIFY`,
and `ROLLBACK_DECISION_NOOP` for all other states. No side effects.

On-device: `rollback_decision.h` includes the real `esp_ota_ops.h`.
Native: `ROLLBACK_DECISION_NATIVE_TEST` supplies a minimal enum stub with the
same numeric values as ESP-IDF.

Tested natively: 6 cases in `test/native/test_rollback_decision/`.
