# test/native -- Native Host Unit Tests

Unity-based unit tests that run on the host machine with no ESP32-S3, no
emulator, and no network. Run them via:

```
pio test -e native
```

Each suite lives in its own subdirectory following the convention
`test_X/test_X.c`. PlatformIO discovers them automatically from the
`[env:native]` environment defined in `platformio.ini`.

## Build wiring

The `[env:native]` environment in `platformio.ini` sets the following
compile-time flags so that the production sources under `lib/` build on the
host without an ESP-IDF toolchain:

| Flag | Effect |
|---|---|
| `RING_NATIVE=1` | Selects the POSIX `pthread_mutex_t` / `pthread_cond_t` backend in `lib/ring/ring.c` and the `pthread_mutex_t`-backed circular buffer in `lib/scrollback/scrollback.c` |
| `UNIT_TEST` | Selects the native circular-buffer struct layout in `lib/scrollback/scrollback.c` |
| `ROLLBACK_DECISION_NATIVE_TEST` | Supplies an inline `esp_ota_img_states_t` enum so `lib/rollback_decision/` builds with no ESP-IDF header |
| `CRED_STORE_NATIVE_TEST` | Swaps the ESP-IDF NVS calls in `lib/cred_store/` for an in-memory backend so the parse + load/save logic runs natively |
| `SCEP_TRANSPORT_NATIVE_TEST` | Suppresses the extern linker-section symbols in `scep_transport.h` so the header parses on the host |
| `SCEP_CA_PEM_EMBEDDED` | Suppresses the linker-script cert symbols (a stub provides them) |

Two include paths are added: `test/stubs` (puts `esp_err.h`, `esp_log.h`,
`esp_http_client.h`, `esp_heap_caps.h`, `freertos/`, and `mbedtls/` on the
search path) and `test/stubs/wolfssl` (the wolfCrypt OpenSSL shim headers).
The `extra_scripts = test/scripts/native_link_openssl.py` hook appends
`-lcrypto` and `-lmbedcrypto` / `-lmbedx509` / `-lmbedtls` to the link step;
crypto suites resolve symbols from the host's system OpenSSL 3 and
mbedTLS.

## Suites

Each subdirectory is one Unity suite. The list below is a one-liner per
directory; cross-reference the corresponding `lib/<name>/README.md` for the
full description of what is exercised.

| Suite | Module under test |
|---|---|
| `test_ring` | `lib/ring/` -- FIFO, wrap-around, close-unblocks, backpressure, `ring_try_send`, `ring_reopen` |
| `test_bridge` | `lib/bridge/` -- full-duplex ordering, stop flag, error termination |
| `test_bridge_scrollback` | bridge + scrollback interaction during SSH session replay |
| `test_cdc_drain` | `lib/usb_cdc_drain/` -- drain-to-empty, error stop, ring full/closed |
| `test_term_resize` | `lib/term_resize/` -- xterm CSI formatter incl. boundary cases |
| `test_scrollback` | `lib/scrollback/` -- circular buffer + line scan + ANSI formatters |
| `test_pubkey_auth` | `lib/pubkey_auth/` -- OpenSSH line parsing + hash framing |
| `test_host_key` | `lib/pubkey_auth/` -- `format_fingerprint()` colon-hex formatting |
| `test_auth_check` | `lib/pubkey_auth/` -- constant-time match + multi-key iteration |
| `test_user_class` | `lib/pubkey_auth/` -- `tty` / `ota` username classifier |
| `test_rollback_decision` | `lib/rollback_decision/` -- pure decision over all `esp_ota_img_states_t` values |
| `test_ssh_keepalive` | `lib/ssh_keepalive/` -- idle timer + drop-after-N-misses logic |
| `test_mdns_dispatch` | `lib/mdns_dispatch/` -- task-create retry policy |
| `test_ntp_config` | `main/wifi.c` NTP server-list parsing + timezone macros |
| `test_config_bounds` | `config.h` bounds-check macros |
| `test_scep_proto` | `lib/scep_proto/` -- CSR + pkiMessage build/reparse, transaction ID, error paths |
| `test_scep_transport` | `lib/scep_transport/` against a stub `esp_http_client` |
| `test_cred_store` | `lib/cred_store/` -- NVS-backed save/load, `parse_not_after` |
| `test_cred_store_integration` | end-to-end: FakeNdesCA-issued cert -> parse -> save -> load |
| `test_wifi_state` | `lib/wifi_state/` -- bootstrap state-machine truth table |
| `test_cert_renewer` | `lib/cert_renewer/` -- clock + renewal-window decision |
| `test_udp_log` | `lib/udp_log/` -- two layers: (1) vprintf hook formatting / truncation / ANSI passthrough / UART chain order / fd-not-ready; (2) accumulator buffering / overflow-flush / idle-flush / `#<seq>\n` header / sequence increment / fd-unavailable still bumps seq / oversize-line standalone send |
| `test_util` | `lib/util/` -- `zeroize()` clears buffer / zero-len no-op / single-byte |

## Conventions

- Each suite is self-contained: `test_X/test_X.c` holds all test cases and
  the `main()` entry point that calls `UNITY_BEGIN()`, the `RUN_TEST`
  list, and `UNITY_END()`.
- Crypto-touching suites pick up OpenSSL 3 via the `test/stubs/wolfssl/`
  shim headers and `-lcrypto`. SCEP / cred_store suites additionally link
  the host's system mbedTLS.
- Suites with no platform dependency (`test_ring`, `test_bridge`,
  `test_bridge_scrollback`, `test_cdc_drain`, `test_term_resize`,
  `test_scrollback`, `test_rollback_decision`, `test_user_class`,
  `test_wifi_state`, `test_cert_renewer`, `test_config_bounds`) require
  no stub layer at all.

## Adding a new suite

1. Create `test/native/test_X/test_X.c` with a `main()` that calls
   `UNITY_BEGIN()`, lists each test via `RUN_TEST`, and returns
   `UNITY_END()`.
2. If the suite needs an ESP-IDF or mbedTLS facility that the existing
   stubs do not provide, add a header under `test/stubs/` (see
   [`test/stubs/README.md`](../stubs/README.md)).
3. If the suite needs a new compile-time flag to slip past an on-device
   header, add the flag to `[env:native]` `build_flags` in
   `platformio.ini` and document it in the table above.
4. Run `pio test -e native -f test_X` to verify in isolation, then `pio
   test -e native` to confirm the suite plays well with the rest.
