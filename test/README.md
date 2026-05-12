# esp-tty Test Suite

The test suite has three tiers: native host unit tests, integration and system
scripts, and a simulator configuration for interactive or scripted firmware
runs. Each tier has its own subdirectory with a detailed README; this document
is a concise overview and entry point.

## Tiers at a glance

| Tier | Directory | How to run | Requires hardware? |
|---|---|---|---|
| Native unit tests | [`test/native/`](native/README.md) | `pio test -e native` | No |
| Integration scripts | [`test/scripts/`](scripts/README.md) | `bash` / `python3` per script | No (QEMU) |
| Simulator config | [`test/wokwi/`](wokwi/README.md) | Wokwi extension or wokwi.com | No |

## Native unit tests

All 13 Unity suites run on the host with no ESP32-S3, no emulator, and no
network. Expected result: **155 test cases: 155 succeeded**.

| Suite | Cases | What it tests |
|---|---|---|
| `test_ring` | 17 | Ring buffer FIFO, wrap-around, close-unblocks-recv, backpressure, `ring_try_send`, `ring_reopen` |
| `test_bridge` | 5 | Full-duplex ordering, stop-flag termination, no-drop guarantee, terminates on write error |
| `test_bridge_scrollback` | 4 | Bridge + scrollback interaction during replay |
| `test_cdc_drain` | 6 | `usb_cdc_drain()` -- multi-chunk drain, sub-64-byte chunks, stops on read error, ring-full/closed, early-exit |
| `test_term_resize` | 10 | `term_resize_format()` -- typical, boundary, zero cols/rows reject, NULL out, buffer too small, UINT32_MAX |
| `test_scrollback` | 26 | Push/get round-trips, `scrollback_count_newlines()`, `scrollback_format_header()`, `SCROLLBACK_FOOTER` constant |
| `test_ota_stream` | 7 | `ota_stream_read_all()` -- geometric growth, transient retries, OOM, empty input, max_bytes, zero-retries |
| `test_pubkey_auth` | 12 | OpenSSH pubkey line parsing, base64 decode, SHA-256 hash framing, 513-byte overflow guard |
| `test_host_key` | 9 | `format_fingerprint()` -- colon-separated hex formatting, boundary/null cases |
| `test_auth_check` | 10 | `pubkey_auth_check()` accept + reject paths, multi-key iteration, constant-time byte comparison |
| `test_user_class` | 23 | `pubkey_classify_user()` -- `tty`/`ota` accept; length/case/whitespace/unicode/NUL edge cases reject |
| `test_ota_verify` | 20 | OTA image format, ECDSA verify, AES-GCM decrypt, edge cases (empty, wrong version, tampered byte) |
| `test_rollback_decision` | 6 | `rollback_decide()` for each `esp_ota_img_states_t` value |

Crypto suites link against OpenSSL 3 via thin shim headers in
[`test/stubs/`](stubs/README.md) rather than wolfCrypt or ESP-IDF, so the
native environment needs no firmware toolchain. Non-crypto suites require no
stub layer at all.

## Integration scripts

Six scripts test properties beyond the scope of unit tests: build
reproducibility, patch idempotency, OTA key generation, OTA signer/verifier
round-trip, and full firmware boot under QEMU. All run on a Linux host; none
require real ESP32-S3 hardware.

| Script | What it does |
|---|---|
| `test_qemu_boot.py` | Builds the wokwi firmware, merges a 16 MB flash image, boots under `qemu-system-xtensa`, asserts SSH listen + NVS keygen log lines within the timeout |
| `test_qemu_nvs_persistence.py` | Runs two back-to-back QEMU boots; asserts the host-key fingerprint is identical across reboots |
| `test_clean_build.sh` | Wipes build cache, substitutes a minimal `config.h`, runs `pio run -e wokwi` and `pio test -e native`, confirms patch idempotency on a second incremental build |
| `test_ota_signer_roundtrip.sh` | Generates OTA keys in a temp dir, signs dummy firmwares, compiles `roundtrip_verify.c`, asserts valid accept and tampered-byte reject |
| `test_gen_ota_key.sh` | Tests `scripts/gen_ota_key.sh`: fresh-run generation, refusal on re-run, refusal on partial key state, re-run after deletion, file content/size sanity |
| `test_apply_patches.py` | Unit-tests `scripts/apply_managed_patches_cmake.py`: happy-path apply, idempotency, malformed-patch error, missing-patches-dir no-op |

See [`test/scripts/README.md`](scripts/README.md) for prerequisites and exact
invocation syntax.

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
- **`wifi.c` -- event handlers and reconnect logic**: requires a FreeRTOS event
  loop; no host-side mock exists.
- **`usb_cdc.c` -- TinyUSB RX/TX wiring**: the drain loop is extracted to
  `lib/usb_cdc_drain/` and tested in `test_cdc_drain`; the callback
  registration and `usb_tx_task` loop require hardware.
- **`ssh_server.c` -- accept loop, session preemption, pump tasks**: requires
  wolfSSH and a live TCP connection. Pure-formatter helpers it uses are covered
  in their own suites.
- **`ota_session.c` -- full streaming verify-and-flash flow**: the accumulator
  is tested in `test_ota_stream`; the wolfSSH integration and `esp_ota_*` flash
  writes need hardware or deep mocking.
- **E2E SSH session into QEMU**: `qemu-system-xtensa` for ESP32-S3 has no NIC
  emulation the firmware can drive. A full session test requires real hardware.
- **`main.c` -- NVS encryption init flow**: encrypted NVS cannot be inspected
  from the host; tested only indirectly via QEMU boot log.

## Security model note

The device uses NVS encryption (AES-XTS-256) with the key stored in the
`nvs_keys` partition -- no eFuses are burned. This is intentional: the project
leaves all eFuse bits unprogrammed so the device can be reflashed freely during
development. The trade-off is that an attacker with physical flash access can
extract the NVS key. The SSH host key and authorized public key are the only
secrets stored in NVS; neither enables privilege escalation beyond serial
console access.
