# esp-tty Test Suite

The test suite has three tiers: native host unit tests, integration and system
scripts, and a simulator configuration for interactive or scripted firmware
runs. Each tier has its own subdirectory with a detailed README; this document
is a concise overview and entry point.

## Tiers at a glance

| Tier | Directory | How to run | Requires hardware? |
|---|---|---|---|
| Native unit tests | [`test/native/`](native/README.md) | `pio test -e native` | No |
| Integration scripts | [`test/scripts/`](scripts/README.md) | `bash` / `pytest` per script | No (QEMU) |
| On-device smoke | [`test/embedded/`](embedded/) | `pio test -e esp32s3` (hardware) | Yes |
| Simulator config | [`test/wokwi/`](wokwi/README.md) | Wokwi extension or wokwi.com | No |

## Native unit tests

All 20 Unity suites run on the host with no ESP32-S3, no emulator, and no
network. Expected result: **236 test cases: 236 succeeded**.

| Suite | Cases | What it tests |
|---|---|---|
| `test_ring` | 17 | Ring buffer FIFO, wrap-around, close-unblocks-recv, backpressure, `ring_try_send`, `ring_reopen` |
| `test_bridge` | 5 | Full-duplex ordering, stop-flag termination, no-drop guarantee, terminates on write error |
| `test_bridge_scrollback` | 4 | Bridge + scrollback interaction during replay |
| `test_cdc_drain` | 6 | `usb_cdc_drain()` -- multi-chunk drain, sub-64-byte chunks, stops on read error, ring-full/closed, early-exit |
| `test_term_resize` | 10 | `term_resize_format()` -- typical, boundary, zero cols/rows reject, NULL out, buffer too small, UINT32_MAX |
| `test_scrollback` | 26 | Push/get round-trips, `scrollback_count_newlines()`, `scrollback_format_header()`, `SCROLLBACK_FOOTER` constant |
| `test_pubkey_auth` | 12 | OpenSSH pubkey line parsing, base64 decode, SHA-256 hash framing, 513-byte overflow guard |
| `test_host_key` | 9 | `format_fingerprint()` -- colon-separated hex formatting, boundary/null cases |
| `test_auth_check` | 10 | `pubkey_auth_check()` accept + reject paths, multi-key iteration, constant-time byte comparison |
| `test_user_class` | 23 | `pubkey_classify_user()` -- `tty`/`ota` accept; length/case/whitespace/unicode/NUL edge cases reject |
| `test_rollback_decision` | 6 | `rollback_decide()` for each `esp_ota_img_states_t` value |
| `test_ssh_keepalive` | 11 | SSH-level keepalive timer + drop logic |
| `test_mdns_dispatch` | 6 | mDNS service registration dispatch, task-create failure / retry |
| `test_ntp_config` | 7 | NTP server-list parsing, timezone macro propagation |
| `test_config_bounds` | 7 | `config.h` bounds-check macros (SSID length, retry counts, etc.) |
| `test_scep_proto` | 24 | SCEP wire-protocol library: CSR build + reparse, transaction ID, error paths, NULL guards |
| `test_cred_store` | 13 | NVS-backed cred store: save/load/clear round-trip, `parse_not_after`, NULL/sentinel guards |
| `test_cred_store_integration` | 7 | End-to-end: FakeNdesCA-issued cert DER → `parse_not_after` → save/load round-trip |
| `test_wifi_state` | 21 | `wifi_decide_next_step()` truth table including no-NTP override |
| `test_cert_renewer` | 12 | `cert_renewer_decide()` -- clock-plausibility, renewal window, sentinel `not_after=0` |

Crypto suites link against OpenSSL 3 + system libmbedtls via thin shim headers in
[`test/stubs/`](stubs/README.md); the native environment needs no firmware
toolchain.

## Integration scripts

Mix of pytest-driven Python and shell scripts that test properties beyond the
scope of unit tests: build reproducibility, patch idempotency, OTA / SCEP
protocol round-trips, and full firmware boot under QEMU. All run on a Linux
host; none require real ESP32-S3 hardware.

| Script | What it does |
|---|---|
| `test_qemu_boot.py` | Builds the wokwi firmware, merges a 16 MB flash image, boots under `qemu-system-xtensa`, asserts SSH listen + NVS keygen log lines within the timeout |
| `test_qemu_nvs_persistence.py` | Runs two back-to-back QEMU boots; asserts the host-key fingerprint is identical across reboots |
| `test_clean_build.sh` | Wipes build cache, substitutes a minimal `config.h`, runs `pio run -e wokwi` and `pio test -e native`, confirms patch idempotency on a second incremental build |
| `test_apply_patches.py` | Unit-tests `scripts/apply_managed_patches_cmake.py`: happy-path apply, idempotency, malformed-patch error, missing-patches-dir no-op |
| `test_ota_send_unit.py` | Unit tests for the OTA-over-SSH client: HKDF, AES-GCM roundtrip, key derivation, framing |
| `test_ota_protocol_e2e.py` | End-to-end OTA protocol against an in-process FakeDevice — success, tampered, truncated, replay |
| `test_scep_protocol_e2e.py` | End-to-end SCEP enrollment against an in-process FakeNdesCA — success, failure, pending, malformed CertRep, single/multi-cert bundle parsing |

Run the pytest tests with `venv/bin/pytest test/scripts/test_*.py`.
See [`test/scripts/README.md`](scripts/README.md) for prerequisites and exact
invocation syntax.

## On-device smoke

[`test/embedded/`](embedded/) holds firmware tests that link against the full
ESP-IDF stack and require real hardware. Currently a single suite,
`test_scep_proto_smoke`, exercises the full SCEP wire-protocol roundtrip
(`wc_PKCS7_*` etc.) which can't be reached natively. Gated on a build flag;
not run as part of normal CI.

## Simulator

The [`test/wokwi/`](wokwi/README.md) directory holds the Wokwi simulator
manifest (`wokwi.toml`) and circuit diagram (`diagram.json`) for the `wokwi`
PlatformIO environment. That environment builds with `BRIDGE_LOOPBACK=1`, which
wires the two ring buffers back-to-back instead of connecting to a USB host,
allowing the SSH bridge loop to run in a network-only simulated environment. The
same binary produced by `pio run -e wokwi` is used by `test_qemu_boot.py` and
`test_qemu_nvs_persistence.py`.

## Known coverage gaps

The following components have no automated test coverage. They require real
hardware or deep mocking that does not yet exist:

- **`host_key.c` -- key generation + NVS persistence**: needs wolfCrypt RNG and
  NVS flash emulation. Only `format_fingerprint()` is tested natively.
- **`wifi.c` -- event handlers and reconnect logic**: the pure decision
  function (`wifi_decide_next_step`) is fully tested in `test_wifi_state`;
  the imperative `wifi_mode_psk` / `wifi_mode_enterprise` wrappers that drive
  the ESP-IDF event loop and EAP supplicant require hardware.
- **`usb_cdc.c` -- TinyUSB RX/TX wiring**: the drain loop is extracted to
  `lib/usb_cdc_drain/` and tested in `test_cdc_drain`; the callback
  registration and `usb_tx_task` loop require hardware.
- **`ssh_server.c` -- accept loop, session preemption, pump tasks**: requires
  wolfSSH and a live TCP connection. Pure-formatter helpers it uses are covered
  in their own suites.
- **`ota_session.c` -- full streaming verify-and-flash flow**: the wire
  protocol is tested in `test_ota_protocol_e2e` (Python FakeDevice); the
  wolfSSL X25519/AES-GCM integration and `esp_ota_*` flash writes need
  hardware.
- **`scep_proto.c` -- full PKCS#7 SignedData(EnvelopedData(CSR)) build +
  CertRep parse**: wire format is tested in `test_scep_protocol_e2e` (Python
  FakeNdesCA); mbedTLS-on-device path is exercised by the on-device smoke
  suite in `test/embedded/`.
- **`cert_renewer.c` -- FreeRTOS background task**: pure decision function
  (`cert_renewer_decide`) is fully tested in `test_cert_renewer`; the
  imperative SCEP-renewal + EAP-reconfig + reconnect path requires hardware.
- **E2E SSH session into QEMU**: `qemu-system-xtensa` for ESP32-S3 has no NIC
  emulation the firmware can drive. A full session test requires real hardware.
- **`main.c` -- NVS encryption init flow**: encrypted NVS cannot be inspected
  from the host; tested only indirectly via QEMU boot log.

## Security model note

The device uses NVS encryption (AES-XTS-256) with the key stored in the
`nvs_keys` partition -- no eFuses are burned. This is intentional: the project
leaves all eFuse bits unprogrammed so the device can be reflashed freely during
development. The trade-off is that an attacker with physical flash access can
extract the NVS key. The SSH host key, authorised public keys, and the
SCEP-enrolled client cert + private key are stored in NVS; none enable
privilege escalation beyond serial console access.
