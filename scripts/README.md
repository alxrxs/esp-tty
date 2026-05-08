# scripts/ — Build and Key Management Scripts

```
scripts/
  gen_ota_key.sh                   Generate the OTA signing keypair and AES key
  sign_firmware.py                 Sign and encrypt a firmware binary for OTA
  gen_eap_certs_asm.py             PlatformIO hook: pre-generate EAP-TLS cert .S files
  apply_managed_patches_cmake.py   Apply patches to managed_components/ at cmake time
  apply_managed_patches.py         Alternate SCons entry point (unused in current build)
  fetch_managed_components.py      Legacy dependency fetcher (unused)
```

## gen_ota_key.sh

Generates the three files required to sign and decrypt OTA firmware images:

- `ota_keys/sign.key.pem` — ECDSA-P256 private key (gitignored, keep secret)
- `ota_keys/sign.pub.pem` — ECDSA-P256 public key (gitignored, embedded in firmware)
- `ota_keys/aes.key` — 32 raw bytes, AES-256-GCM encryption key (gitignored, embedded in firmware)

The script is idempotent in the safe direction: it refuses to overwrite any
existing key file. This prevents accidental key rotation that would break
signed firmware delivery to fielded devices. To regenerate, delete the three
files explicitly (understanding that doing so invalidates all previously signed
images for the current firmware's key set).

Requires: `openssl` in PATH.

The `OTA_KEYS_DIR` environment variable overrides the output directory (used by
`test/scripts/test_gen_ota_key.sh` to keep test keys isolated from the project's
actual `ota_keys/`).

Usage:
```
bash scripts/gen_ota_key.sh
```

## sign_firmware.py

Signs and encrypts a compiled firmware binary, producing a `.ota` file for
delivery via `ssh ota@<device>`. The output format is:

```
[8B magic "ESPOTA1\0"][4B version][4B plaintext_len][12B AES-GCM IV]
[16B AES-GCM tag][N bytes ciphertext][64B ECDSA-P256 signature (r||s)]
```

The ECDSA signature covers `SHA-256(magic + version + plaintext_len + IV +
tag + ciphertext)`. The AES-GCM tag covers the ciphertext only (no AAD).

The script performs a self-test after writing the output: it re-reads the file,
verifies the magic, version, and ECDSA signature, and exits non-zero if the
self-test fails.

Requires: `python3-cryptography` (`pip install cryptography`). The fallback
`openssl` subprocess path does not support GCM tag extraction and will raise an
error; install the Python package.

Usage:
```
python3 scripts/sign_firmware.py .pio/build/esp32s3/firmware.bin
# Output: .pio/build/esp32s3/firmware.bin.ota

python3 scripts/sign_firmware.py firmware.bin --key ota_keys/sign.key.pem \
    --aes ota_keys/aes.key --out firmware.ota
```

## gen_eap_certs_asm.py

PlatformIO `extra_scripts = post:` hook. Works around a PlatformIO/ESP-IDF
scheduling issue: ESP-IDF marks the EAP-TLS certificate assembly files
(`ca.pem.S`, `client.crt.S`, `client.key.S`) as generated sources in the cmake
codemodel, but PlatformIO replaces the ninja build with its own SCons graph and
never invokes the cmake custom command that would generate them. On a clean build
the .S files do not exist yet when SCons tries to assemble them, causing an
immediate failure.

The hook solves this by invoking ESP-IDF's `data_file_embed_asm.cmake` script
directly at PlatformIO script-eval time (before SCons evaluates the build graph),
writing the .S files into the PlatformIO build directory where SCons expects
them. The same hook also pre-generates the OTA public key and AES key assembly
files that are embedded via `EMBED_TXTFILES`/`EMBED_FILES`.

This hook runs for both `esp32s3` and `wokwi` environments. It is a no-op if
the cert/key files are absent.

## apply_managed_patches_cmake.py

Called by the root `CMakeLists.txt` via `execute_process` during the cmake
configure step. Scans `patches/<component>/*.patch` files and applies each one
to the corresponding `managed_components/<component>/` directory using `patch -p1`.

Idempotency: before applying, the script runs `patch --dry-run -R` (reverse
apply check). If the patch is already applied, it prints "Already applied" and
skips. This means `pio run` can be run multiple times without error even after
the managed_components/ directory is re-fetched.

See `patches/README.md` for the list of patches and the reason they exist.

Usage (invoked automatically by cmake; can also be run manually):
```
python3 scripts/apply_managed_patches_cmake.py /path/to/project
```

## apply_managed_patches.py

An alternative entry point for the same patch logic, written as a PlatformIO
SCons `extra_scripts = pre:` hook. It is not wired into `platformio.ini` in the
current build; the cmake entry point (`apply_managed_patches_cmake.py`) is used
instead because it runs earlier in the dependency resolution sequence. This file
is retained for reference.

## fetch_managed_components.py

Legacy script that manually fetched wolfSSL and wolfSSH component archives before
the project switched to the IDF component manager (`idf_component.yml`). It is
no longer used and is retained for reference only.
