# test/native — Native Host Unit Tests

This directory contains all Unity-based unit tests that run on the host machine
with no ESP32-S3 hardware, no emulator, and no network. They are executed via:

```
pio test -e native
```

Expected result: **155 test cases: 155 succeeded**

Each suite lives in its own subdirectory following the naming convention
`test_X/test_X.c`. PlatformIO discovers them automatically from the `native`
environment defined in `platformio.ini`. All 13 suites use the Unity test
framework and link against the OpenSSL 3 EVP stubs found in
`test/stubs/wolfssl/` rather than wolfCrypt or wolfSSH, so the native
environment never requires ESP-IDF headers or the full TLS library stack.

## Suites

| Suite | Cases | What it tests |
|---|---|---|
| `test_ring` | 17 | Ring buffer FIFO, wrap-around, close-unblocks-recv, backpressure, `ring_try_send` (incl. exact partial-write bound and no-deadlock under contention), `ring_reopen` (clears closed flag, drains stale data, idempotent on open ring, recv-blocks-for-new-data after reopen) |
| `test_bridge` | 5 | Full-duplex ordering, stop-flag termination, no-drop guarantee, terminates on write error, stop observed before next read |
| `test_bridge_scrollback` | 4 | Bridge + scrollback interaction during replay |
| `test_cdc_drain` | 6 | `usb_cdc_drain()` — multi-chunk drain until empty, sub-64-byte chunks, stops on read error, continues when ring full / closed, zero-on-first-call early exit |
| `test_term_resize` | 10 | `term_resize_format()` — typical 80x24, 1x1, large, zero cols/rows reject, NULL out, buffer too small, exact-fit boundary, UINT32_MAX |
| `test_scrollback` | 26 | Push/get round-trips, `scrollback_count_newlines()` (none/single/multiple/consecutive/CR/binary), `scrollback_format_header()` (zero/typical/too-small/NULL/negative/exact-fit/large), `SCROLLBACK_FOOTER` constant |
| `test_ota_stream` | 7 | `ota_stream_read_all()` — geometric buffer growth, transient zero-return retries, OOM partial cleanup, empty input, exceeds max_bytes, small reads, zero-retries exhausted |
| `test_pubkey_auth` | 12 | OpenSSH pubkey line parsing, base64 decode, SHA-256 hash framing, 513-byte overflow guard, 512-byte exact-fit boundary |
| `test_host_key` | 9 | `format_fingerprint()` — colon-separated hex formatting, boundary/null cases |
| `test_auth_check` | 10 | `pubkey_auth_check()` accept + reject paths, multi-key iteration (matches first/last/none of N), zero-count early return, constant-time all-bytes-compared |
| `test_user_class` | 23 | `pubkey_classify_user()` — `tty` and `ota` accept, length/case/whitespace/unicode/embedded-NUL/very-long edge cases all reject |
| `test_ota_verify` | 20 | OTA image format, ECDSA verify, AES-GCM decrypt, edge cases (empty image, wrong version, length mismatch, abort paths, malformed PEM) |
| `test_rollback_decision` | 6 | `rollback_decide()` for each `esp_ota_img_states_t` value |

## Conventions

- Each suite is self-contained: `test_X/test_X.c` holds all test cases and the
  `main()` entry point that calls `UNITY_BEGIN()`, the `RUN_TEST` list, and
  `UNITY_END()`.
- Crypto suites (`test_pubkey_auth`, `test_host_key`, `test_auth_check`,
  `test_ota_verify`) link against OpenSSL 3 via the thin shim headers in
  `test/stubs/wolfssl/`. This lets the same production source files under `lib/`
  be compiled without modification on the host.
- Non-crypto suites (`test_ring`, `test_bridge`, `test_bridge_scrollback`,
  `test_cdc_drain`, `test_scrollback`, `test_term_resize`, `test_ota_stream`,
  `test_user_class`, `test_rollback_decision`) require no stub layer at all.

For the full test plan — including the QEMU boot smoke test, OTA signer
round-trip script, known coverage gaps, and security model notes — see
[test/README.md](../README.md).
