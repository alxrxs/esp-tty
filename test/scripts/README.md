# test/scripts/

This directory holds the integration and system-test layer of the esp-tty
test suite. The scripts here cover properties beyond the reach of the
native unit tests in `test/native/`: build reproducibility, patch
idempotency, OTA-over-SSH and SCEP protocol roundtrips against
in-process fakes, and full firmware boot under QEMU. No real ESP32-S3 is
needed; everything runs on a Linux host. See `test/README.md` for the
suite-wide overview and the documented coverage gaps.

## Scripts

| File | Description |
|---|---|
| `test_qemu_boot.py` | Builds the wokwi firmware, merges a 16 MB flash image with `esptool`, boots under `qemu-system-xtensa`, and asserts the SSH server starts and key-generation log lines appear within the timeout |
| `test_qemu_nvs_persistence.py` | Runs two back-to-back QEMU boots against the same flash file and verifies the host-key fingerprint persists across reboots |
| `test_clean_build.sh` | Wipes the build cache, substitutes a minimal `config.h` from the example, runs `pio run -e wokwi` and `pio test -e native`, then a second incremental build to confirm patch idempotency; restores the original `config.h` on exit |
| `test_apply_patches.py` | Unit-tests `scripts/apply_managed_patches_cmake.py` with synthetic temp directories: happy-path apply, idempotency (skip-if-applied), malformed-patch error, missing-patches-dir no-op |
| `test_ota_send_unit.py` | Unit tests for the OTA-over-SSH client: HKDF, AES-GCM roundtrip, key derivation, framing |
| `test_ota_protocol_e2e.py` | End-to-end OTA protocol against an in-process `FakeDevice` -- success, tampered ciphertext, truncated transfer, replay |
| `test_scep_protocol_e2e.py` | End-to-end SCEP enrolment against an in-process `FakeNdesCA` -- success, failure, pending, malformed CertRep, single/multi-cert bundle parsing |
| `regen_cred_store_fixtures.py` | Developer utility: regenerates the DER fixtures baked into `test/native/test_cred_store_integration/` using `FakeNdesCA`. Run only when the fake CA changes; the resulting C file is committed so native tests do not depend on Python at run time |
| `native_link_openssl.py` | PlatformIO `extra_scripts` hook for the `[env:native]` build; appends `-lcrypto` and the host mbedTLS link flags so the OpenSSL- and mbedTLS-backed stubs resolve at link time. Not invoked directly |

## Prerequisites

| Dependency | Used by |
|---|---|
| `qemu-system-xtensa` (Espressif fork, `esp_develop_9.2.2_20250817`) | `test_qemu_boot.py`, `test_qemu_nvs_persistence.py` |
| `esptool.py` (via PlatformIO) | `test_qemu_boot.py` (flash image merge) |
| `pio` / PlatformIO CLI | `test_qemu_boot.py`, `test_qemu_nvs_persistence.py`, `test_clean_build.sh` |
| `python3` (3.8+) | all `.py` scripts |
| `pytest`, `paramiko`, `cryptography` | `test_ota_*`, `test_scep_protocol_e2e.py` (installed by `requirements.txt`) |
| OpenSSL 3 + libmbedtls/libmbedcrypto/libmbedx509 dev libs | `pio test -e native` (resolved via `native_link_openssl.py`) |
| `patch` (GNU) | `test_apply_patches.py` |

The QEMU binary path is expected at
`~/.espressif/tools/qemu-xtensa/esp_develop_9.2.2_20250817/qemu/bin/qemu-system-xtensa`;
override it by editing the `QEMU` constant at the top of each Python QEMU
script. All other tools are assumed to be on `PATH` or installed by
PlatformIO into `~/.platformio/`.

## Running

```sh
venv/bin/pytest test/scripts/test_apply_patches.py
venv/bin/pytest test/scripts/test_ota_send_unit.py
venv/bin/pytest test/scripts/test_ota_protocol_e2e.py
venv/bin/pytest test/scripts/test_scep_protocol_e2e.py
python3 test/scripts/test_qemu_boot.py [--no-build] [--timeout 90]
python3 test/scripts/test_qemu_nvs_persistence.py [--no-build] [--timeout 90]
bash    test/scripts/test_clean_build.sh
```

`venv/bin/pytest test/scripts/test_*.py` runs the pytest tier in one shot.

For the full test-suite overview and known coverage gaps see
`test/README.md`.
