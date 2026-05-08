# esp-tty Test Suite

## Running native unit tests

All native tests run on the host — no ESP32 hardware, no emulator, no network.

```
pio test -e native
```

Expected output: **26 test cases: 26 succeeded**

Tests are in `test/native/` and cover:

| Suite | Cases | What it tests |
|---|---|---|
| `test_ring` | 4 | Ring buffer FIFO, wrap-around, close-unblocks-recv, backpressure |
| `test_bridge` | 3 | Full-duplex bridge ordering, stop-flag termination, no-drop guarantee |
| `test_pubkey_auth` | 10 | OpenSSH pubkey line parsing, base64 decode, SHA-256 hash computation |
| `test_host_key` | 9 | `format_fingerprint()` — colon-separated hex formatting, boundary/null cases |

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
- **`usb_cdc.c` — TinyUSB RX/TX callbacks**: could be mocked but has not been.
- **`ssh_server.c` — accept loop, session takeover, pump task**: requires
  wolfSSH + a live TCP connection; not feasible natively.
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
