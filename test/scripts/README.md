# test/scripts/

This directory contains the integration and system-test suite for the
esp-tty ESP32-S3 SSH-to-USB-CDC bridge firmware. The scripts here test
properties that the native unit tests (in `test/native/`) cannot: build
reproducibility, patch-application correctness, OTA key generation and
signer/verifier roundtrip across the host/device boundary, and full
firmware boot behavior under QEMU. No real ESP32-S3 hardware is needed;
all tests run on a Linux development host. See `test/README.md` for the
full test-suite overview, including the native unit-test inventory and
the documented coverage gaps.

## Scripts

| File | Description |
|---|---|
| `test_qemu_boot.py` | Builds the wokwi firmware, merges a 16 MB flash image with esptool, boots under qemu-system-xtensa, and asserts the SSH server starts and key-generation log lines appear within the timeout. |
| `test_qemu_nvs_persistence.py` | Runs two back-to-back QEMU boots against the same flash file and verifies that the NVS write path (boot 1) and read/regenerate path (boot 2) both produce a working SSH listener. |
| `test_clean_build.sh` | Wipes build cache, substitutes a minimal `config.h` from the example, runs `pio run -e wokwi` and `pio test -e native`, then runs a second incremental build to confirm patch-idempotency; restores the original `config.h` on exit. |
| `test_ota_signer_roundtrip.sh` | Generates OTA keys in a temp directory, signs dummy firmwares, compiles `roundtrip_verify.c` with gcc, and asserts the verifier accepts a valid image and rejects a tampered byte or an empty image. |
| `test_gen_ota_key.sh` | Tests `scripts/gen_ota_key.sh`: verifies fresh-run key generation, refusal on re-run, refusal on partial key state, a successful re-run after deletion, and content/size sanity on the generated files. |
| `test_apply_patches.py` | Unit-tests `scripts/apply_managed_patches_cmake.py` using synthetic temp directories: happy-path apply, idempotency (skip-if-applied), malformed-patch error, and missing-patches-dir no-op. |
| `native_link_openssl.py` | PlatformIO `extra_scripts` hook for the `native` environment; appends `-lcrypto` so the wolfCrypt/mbedtls OpenSSL stubs can resolve EVP symbols from the host OpenSSL 3 library. Not invoked directly. |
| `roundtrip_verify.c` | Standalone C program compiled by `test_ota_signer_roundtrip.sh`; calls `ota_verify_begin`/`ota_verify_feed`/`ota_verify_end` on a signed image and exits 0 on `OTA_VERIFY_OK` or 1 on failure. Accepts `--tamper-byte <offset>` to corrupt one byte before verification. |

## Prerequisites

| Dependency | Used by |
|---|---|
| `qemu-system-xtensa` (Espressif fork, `esp_develop_9.2.2_20250817`) | `test_qemu_boot.py`, `test_qemu_nvs_persistence.py` |
| `esptool.py` (via PlatformIO) | `test_qemu_boot.py` (flash image merge) |
| `pio` / PlatformIO CLI | `test_qemu_boot.py`, `test_qemu_nvs_persistence.py`, `test_clean_build.sh` |
| `openssl` (CLI, version 3) | `test_ota_signer_roundtrip.sh`, `test_gen_ota_key.sh` |
| OpenSSL 3 development headers and `libcrypto` | `test_ota_signer_roundtrip.sh` (gcc compile of `roundtrip_verify.c`) |
| `gcc` | `test_ota_signer_roundtrip.sh` |
| `python3` (3.8+) | all `.py` scripts |
| `patch` (GNU) | `test_apply_patches.py` (invokes `apply_managed_patches_cmake.py`) |

The QEMU binary is expected at
`~/.espressif/tools/qemu-xtensa/esp_develop_9.2.2_20250817/qemu/bin/qemu-system-xtensa`.
The path can be overridden by editing `QEMU` at the top of the Python test
scripts. All other tools are assumed to be on `PATH` or installed by PlatformIO
into `~/.platformio/`.

## Running

Each script is self-contained and exits 0 on success, 1 on failure:

```
python3 test/scripts/test_qemu_boot.py [--no-build] [--timeout 90]
python3 test/scripts/test_qemu_nvs_persistence.py [--no-build] [--timeout 90]
bash    test/scripts/test_clean_build.sh
bash    test/scripts/test_ota_signer_roundtrip.sh
bash    test/scripts/test_gen_ota_key.sh
python3 test/scripts/test_apply_patches.py
```

For the full test strategy, coverage table, and known gaps refer to
`test/README.md`.
