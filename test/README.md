# esp-tty Test Suite

## Running native unit tests

All native tests run on the host — no ESP32 hardware, no emulator, no network.

```
pio test -e native
```

Expected output: **155 test cases: 155 succeeded**

Tests are in `test/native/` and cover:

| Suite | Cases | What it tests |
|---|---|---|
| `test_ring` | 17 | Ring buffer FIFO, wrap-around, close-unblocks-recv, backpressure, `ring_try_send` (incl. exact partial-write bound and no-deadlock under contention), `ring_reopen` (clears closed flag, drains stale data, idempotent on open ring, recv-blocks-for-new-data after reopen) |
| `test_bridge` | 5 | Full-duplex ordering, stop-flag termination, no-drop guarantee, terminates on write error, stop observed before next read |
| `test_bridge_scrollback` | 4 | Bridge + scrollback interaction during replay |
| `test_cdc_drain` | 6 | `usb_cdc_drain()` — multi-chunk drain until empty, sub-64-byte chunks, stops on read error, continues when ring full / closed, zero-on-first-call early exit |
| `test_term_resize` | 10 | `term_resize_format()` — typical 80×24, 1×1, large, zero cols/rows reject, NULL out, buffer too small, exact-fit boundary, UINT32_MAX |
| `test_scrollback` | 26 | Push/get round-trips, `scrollback_count_newlines()` (none/single/multiple/consecutive/CR/binary), `scrollback_format_header()` (zero/typical/too-small/NULL/negative/exact-fit/large), `SCROLLBACK_FOOTER` constant |
| `test_ota_stream` | 7 | `ota_stream_read_all()` — geometric buffer growth, transient zero-return retries, OOM partial cleanup, empty input, exceeds max_bytes, small reads, zero-retries exhausted |
| `test_pubkey_auth` | 12 | OpenSSH pubkey line parsing, base64 decode, SHA-256 hash framing, 513-byte overflow guard, 512-byte exact-fit boundary |
| `test_host_key` | 9 | `format_fingerprint()` — colon-separated hex formatting, boundary/null cases |
| `test_auth_check` | 10 | `pubkey_auth_check()` accept + reject paths, multi-key iteration (matches first/last/none of N), zero-count early return, constant-time all-bytes-compared |
| `test_user_class` | 23 | `pubkey_classify_user()` — `tty` and `ota` accept, length/case/whitespace/unicode/embedded-NUL/very-long edge cases all reject |
| `test_ota_verify` | 20 | OTA image format, ECDSA verify, AES-GCM decrypt, edge cases (empty image, wrong version, length mismatch, abort paths, malformed PEM) |
| `test_rollback_decision` | 6 | `rollback_decide()` for each `esp_ota_img_states_t` value |

The crypto tests use OpenSSL 3 EVP stubs (in `test/stubs/wolfssl/`) instead of
wolfCrypt, so the native environment never links wolfSSH or ESP-IDF.

## Running the QEMU boot smoke test

Builds the wokwi firmware (`BRIDGE_LOOPBACK=1`), merges a 16 MB flash image,
boots it under `qemu-system-xtensa`, and checks for "Listening on TCP port 2222"
within 60 seconds.

```
# Build + boot (full):
python3 test/scripts/test_qemu_boot.py

# Skip rebuild if firmware is already up to date:
python3 test/scripts/test_qemu_boot.py --no-build

# Custom timeout:
python3 test/scripts/test_qemu_boot.py --timeout 90
```

Exit code 0 = SSH server started. Exit code 1 = build failed, crash detected,
or timeout.

The QEMU binary is expected at:
`~/.espressif/tools/qemu-xtensa/esp_develop_9.2.2_20250817/qemu/bin/qemu-system-xtensa`

## Script inventory

| Script | What it does |
|---|---|
| `test/scripts/test_qemu_boot.py` | Builds wokwi firmware, merges flash image, boots in QEMU, asserts SSH listen + NVS keygen + fingerprint regex + ELF symbol checks |
| `test/scripts/test_qemu_nvs_persistence.py` | Boots QEMU twice; asserts the host-key fingerprint is identical across reboots (NVS persistence) |
| `test/scripts/test_clean_build.sh` | Wipes build cache, creates a minimal `config.h` from the example, runs `pio run -e wokwi` and `pio test -e native`, restores original `config.h` |
| `test/scripts/test_ota_signer_roundtrip.sh` | Generates fresh OTA keys in a temp dir, signs a dummy firmware, compiles a standalone C program that calls `ota_verify_begin/feed/end` and asserts success; re-runs with one tampered byte and asserts failure |

## What is NOT tested (known gaps)

The following components are not covered by any automated test. They require
either real hardware or deep mocking that has not been done yet:

- **`host_key.c` — key generation + NVS persistence**: needs wolfCrypt RNG and
  NVS flash emulation. Only `format_fingerprint()` (the formatting helper) is
  tested natively.
- **`wifi.c` — event handlers and reconnect logic**: requires a FreeRTOS event
  loop; no host-side mock exists.
- **`usb_cdc.c` — TinyUSB RX/TX wiring**: the RX FIFO drain loop is extracted
  to `lib/usb_cdc_drain/` and tested in `test_cdc_drain` (6 cases); the
  TinyUSB callback registration and the `usb_tx_task` loop still require
  hardware to exercise.
- **`ssh_server.c` — accept loop, session preemption, pump tasks**: requires
  wolfSSH + a live TCP connection; not feasible natively. The pure-formatter
  helpers it uses (`term_resize_format`, `scrollback_format_header`,
  `scrollback_count_newlines`, `SCROLLBACK_FOOTER`) are tested in their own
  suites.
- **`ota_session.c` — full streaming verify-and-flash flow**: the stream-read
  accumulator is extracted to `lib/ota_stream/` and tested in `test_ota_stream`
  (7 cases); the wolfSSH integration and the `esp_ota_*` flash writes still
  need hardware or deep mocking.
- **E2E SSH connection into QEMU**: `qemu-system-xtensa` for ESP32-S3 has no
  NIC emulation the firmware can drive. A full SSH session test requires real
  ESP32-S3 hardware.
- **`main.c` — NVS encryption init flow**: encrypted NVS cannot be inspected
  from the host; tested only indirectly via QEMU boot log.

## Security model note

The device uses NVS encryption (AES-XTS-256) with the key stored in the
`nvs_keys` partition — **no eFuses are burned**. This is intentional: the
project's hard constraint is to leave all eFuse bits unprogrammed so the device
can be reflashed freely during development. The trade-off is that an attacker
with physical flash access can extract the NVS key. The SSH host key and
authorized public key are the only secrets stored in NVS; neither enables
privilege escalation beyond serial console access.
