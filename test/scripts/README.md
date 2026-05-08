# test/scripts/ — Integration and System Test Runners

These scripts test properties that cannot be verified by the native unit test
suite: build reproducibility, patch application, key generation correctness,
the signer/verifier roundtrip across the host/device boundary, and firmware
boot behaviour under QEMU.

None of these scripts require real ESP32-S3 hardware. QEMU tests require the
Espressif QEMU fork; see `test/README.md` for the expected binary path.

```
test/scripts/
  test_qemu_boot.py            Boot smoke test + assertions
  test_qemu_nvs_persistence.py Two-boot NVS key store/load test
  test_clean_build.sh          Clean-build reproducibility test
  test_ota_signer_roundtrip.sh Host signer <-> on-device verifier roundtrip
  test_gen_ota_key.sh          gen_ota_key.sh correctness test
  test_apply_patches.py        apply_managed_patches_cmake.py unit test
  native_link_openssl.py       PlatformIO extra_script: link -lcrypto for native tests
  roundtrip_verify.c           Standalone C binary used by test_ota_signer_roundtrip.sh
```

## test_qemu_boot.py

Builds the wokwi firmware (`BRIDGE_LOOPBACK=1`), merges a 16 MB flash image
using `esptool.py merge_bin`, and boots it under `qemu-system-xtensa`. Asserts
that the following log lines appear before "Listening on TCP port 2222":

- `NVS keys not found — generating new AES-XTS-256 key` (NVS encryption
  initialises on first boot)
- `Host key SHA-256 fingerprint: <32 colon-separated hex pairs>` (host key
  generated and formatted correctly)

Also checks that none of the failure patterns (`abort() was called`,
`Guru Meditation Error`, `ESP_ERROR_CHECK failed`) appear.

Exit code 0 = all assertions passed. Exit code 1 = build failed, crash
detected, or timeout.

```
python3 test/scripts/test_qemu_boot.py
python3 test/scripts/test_qemu_boot.py --no-build    # skip pio run
python3 test/scripts/test_qemu_boot.py --timeout 90  # extend timeout
```

## test_qemu_nvs_persistence.py

Two-boot NVS persistence test. Boots the same flash image under QEMU twice
using `snapshot=off` so that writes to the NVS data partition (at flash offset
0x9000) are flushed back to the file between boots.

Boot 1: asserts `Generated and stored new ED25519 host key` and SSH server
starts.

Boot 2: asserts SSH server starts again (verifying the boot path is not broken
by the persisted NVS data).

Fingerprint equality between boot 1 and boot 2 is **not** asserted. Due to a
QEMU limitation with the `nvs_keys` partition and the HW-flash-encryption
emulation layer, `nvs_flash_generate_keys` regenerates the AES-XTS-256 key on
boot 2, which makes the boot-1 NVS data unreadable. The module docstring in
`test_qemu_nvs_persistence.py` explains the constraint in full. On real hardware
the keys do persist and fingerprints match across reboots.

```
python3 test/scripts/test_qemu_nvs_persistence.py
python3 test/scripts/test_qemu_nvs_persistence.py --no-build --timeout 90
```

## test_clean_build.sh

Clean-build reproducibility test. Steps:

1. Deletes `managed_components/`, `dependencies.lock`, and
   `.pio/build/wokwi`.
2. Writes a minimal `main/config.h` from `main/config.h.example` with
   placeholder values (saves and restores the real `config.h` via a temp
   file).
3. Runs `pio run -e wokwi` — must succeed.
4. Runs `pio test -e native` — must show all test cases passing.
5. Runs `pio run -e wokwi` a second time (incremental) to verify that the
   patch idempotency check in `apply_managed_patches_cmake.py` does not cause
   errors on the second build.

Restores the original `config.h` on exit (even on failure, via `trap`).

```
bash test/scripts/test_clean_build.sh
```

## test_ota_signer_roundtrip.sh

Tests that firmware signed on the host by `scripts/sign_firmware.py` is
correctly verified by the on-device `ota_verify` library. Steps:

1. Generates fresh OTA keys in a temp directory (isolated from the project's
   `ota_keys/`).
2. Signs a 256-byte deterministic dummy firmware.
3. Compiles `test/scripts/roundtrip_verify.c` with `gcc`, linking
   `lib/ota_verify/ota_verify.c` and the mbedtls OpenSSL stubs from
   `test/stubs/`.
4. Runs `roundtrip_verify` against the signed image — expects `OTA_VERIFY_OK`.
5. Runs `roundtrip_verify` with `--tamper-byte 50` (flips one ciphertext byte)
   — expects ECDSA signature failure.
6. Signs an empty (0-byte) firmware, then verifies the verifier correctly
   returns `OTA_VERIFY_ERR_EMPTY_IMAGE`.
7. Signs a 1 MB pseudo-random firmware and verifies it passes.

Exit code 0 = all cases passed.

```
bash test/scripts/test_ota_signer_roundtrip.sh
```

## test_gen_ota_key.sh

Tests `scripts/gen_ota_key.sh` correctness:

1. Fresh run generates all three key files.
2. A second run refuses when all files are present.
3. Partial state (one file missing) is also refused.
4. After deleting all keys, a second fresh run succeeds.
5. Content checks: `aes.key` is exactly 32 bytes; `sign.pub.pem` starts with
   the correct PEM header and is a valid prime256v1 public key.

All keys are generated in a temp directory (`/tmp/esp-tty-keytest-$$`) via the
`OTA_KEYS_DIR` override; the project's `ota_keys/` is never touched.

```
bash test/scripts/test_gen_ota_key.sh
```

## test_apply_patches.py

Unit tests for `scripts/apply_managed_patches_cmake.py`. Constructs synthetic
`managed_components/` and `patches/` directories in temp directories and
exercises:

1. Happy path: a valid unified diff applies cleanly.
2. Idempotency: applying the same patch a second time prints "Already applied"
   and leaves the file unchanged.
3. Malformed patch: a non-diff file raises `RuntimeError`.
4. Missing `patches/` directory: `apply_patches()` is a no-op (no exception).

Does not modify the real `managed_components/` or `patches/` directories.

```
python3 test/scripts/test_apply_patches.py
```

## native_link_openssl.py

PlatformIO `extra_scripts` hook for the `native` environment. Appends `-lcrypto`
to the native link command so that the wolfCrypt and mbedtls OpenSSL stubs in
`test/stubs/` can resolve `EVP_*` symbols from OpenSSL 3. Not invoked directly.

## roundtrip_verify.c

Standalone C program compiled by `test_ota_signer_roundtrip.sh`. Takes an OTA
image path, public key PEM path, and AES key path as arguments, then calls
`ota_verify_begin` / `ota_verify_feed` / `ota_verify_end` on the image. Exits 0
on `OTA_VERIFY_OK`, 1 on any error. Accepts `--tamper-byte <offset>` to flip one
byte in the image before feeding it to the verifier.
