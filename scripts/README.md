# scripts/ — Build and Key Management Scripts

This directory contains the build-system hooks and developer utilities for the
esp-tty firmware project.  The scripts fall into two groups: those that run
automatically as part of the PlatformIO / CMake build pipeline, and those that
a developer runs once (or rarely) to manage cryptographic key material.  All
scripts are designed to be idempotent or to fail loudly rather than silently
corrupt state.

| Script | When it runs | Purpose |
|---|---|---|
| `fetch_managed_components.py` | PlatformIO `pre:` hook | Populates `managed_components/` before cmake runs |
| `gen_eap_certs_asm.py` | PlatformIO `post:` hook | Pre-generates EAP-TLS cert and OTA key `.S` assembly files |
| `apply_managed_patches_cmake.py` | CMake configure step | Applies `patches/` to `managed_components/` |
| `apply_managed_patches.py` | (not wired; reference only) | Alternate SCons entry point for the same patch logic |
| `detect_upload_port.sh` | `make flash` / `make monitor` | Finds the CH340 USB-UART bridge by VID for flashing |
| `gen_ota_key.sh` | Developer, once per deployment | Generates the ECDSA-P256 signing keypair and AES-256 key |
| `sign_firmware.py` | Developer, each OTA release | Signs and encrypts a built firmware binary for OTA delivery |

## fetch_managed_components.py

PlatformIO `extra_scripts = pre:` hook (declared in `platformio.ini`).
On a clean checkout `managed_components/` is gitignored and absent.
PlatformIO's cmake step fails immediately if `EXTRA_COMPONENT_DIRS` points to a
missing directory.  This script calls the ESP-IDF component manager's Python API
(from the ESP-IDF PlatformIO venv) to run `prepare_dep_dirs` before cmake is
invoked, so `managed_components/` is always present when cmake reads it.

The script uses `managed_components/wolfssl__wolfssl` as a sentinel: if that
directory already exists the fetch is skipped entirely, making repeated `pio
run` invocations fast.  If the ESP-IDF venv Python cannot be located the script
emits a warning and returns without error rather than aborting the build; the
developer is then directed to run `idf.py update-dependencies` manually.

## gen_eap_certs_asm.py

PlatformIO `extra_scripts = post:scripts/gen_eap_certs_asm.py` hook, active for
both the `esp32s3` and `wokwi` environments.  It works around a
PlatformIO/ESP-IDF scheduling conflict: ESP-IDF marks the EAP-TLS certificate
files (`ca.pem.S`, `client.crt.S`, `client.key.S`) and the OTA key files
(`sign.pub.pem.S`, `aes.key.S`) as generated sources in the cmake codemodel, but
PlatformIO replaces the ninja build with its own SCons graph and never invokes
the cmake custom command that would create those `.S` files.  On a clean build the
files do not exist when SCons tries to assemble them, causing an immediate build
failure.

The hook fixes this by invoking ESP-IDF's `data_file_embed_asm.cmake` script
directly at PlatformIO script-evaluation time — before SCons has read the build
graph — writing the `.S` files into `BUILD_DIR` exactly where the cmake codemodel
says they live.  Each file is regenerated only when its source data file is newer
than the existing `.S`, keeping incremental builds efficient.  The hook is a no-op
if the certificate or key source files are absent.

## apply_managed_patches_cmake.py

Called by the root `CMakeLists.txt` via `execute_process` during the cmake
configure step, after the IDF component manager has resolved and fetched
dependencies.  The script scans `patches/<component>/*.patch` and applies each
patch to the matching `managed_components/<component>/` tree using `patch -p1`.

Idempotency is enforced with a two-step check: before applying any patch the
script runs `patch --dry-run -R` (reverse apply).  If the reverse succeeds the
patch is already present and is skipped.  If neither the reverse nor the forward
dry-run succeeds the script raises an error describing the conflict rather than
partially applying the patch.  This design allows `pio run` to be repeated safely
after the managed components directory is deleted and re-fetched.  See
`patches/README.md` for the list of active patches and the rationale for each.

Usage (invoked automatically; can also be run manually for debugging):
```
python3 scripts/apply_managed_patches_cmake.py /path/to/project
```

## apply_managed_patches.py

An alternative entry point for the same patching logic, written as a PlatformIO
SCons `extra_scripts = pre:` hook.  It is not wired into `platformio.ini` in the
current build; the cmake entry point (`apply_managed_patches_cmake.py`) is
preferred because it runs earlier in the dependency resolution sequence, before
SCons reads component sources.  This file is retained for reference in case the
cmake entry point needs to be replaced by a PlatformIO-native hook in a future
toolchain version.

## detect_upload_port.sh

Called by the `Makefile` (`PORT ?= $(shell scripts/detect_upload_port.sh)`) to
resolve the correct serial device for `make flash` and `make monitor`.  The
problem this solves: this firmware exposes the ESP32-S3's native USB as a CDC
ACM device (the SSH-to-USB bridge endpoint), which on Linux and macOS enumerates
under the same filename patterns as a CH340/CH343 USB-UART bridge used for
flashing.  Filename matching alone cannot distinguish the two interfaces.

The script therefore queries the USB Vendor ID instead of the device name.
On Linux it globs `/dev/serial/by-id/usb-1a86_*` (WCH VID `0x1a86`).  On macOS
it walks the `IOUSBHostDevice` IORegistry tree via `ioreg`, filters on
`idVendor = 6790` (decimal equivalent of `0x1a86`), and extracts the first
`IOCalloutDevice` path.  On other platforms the script emits nothing and the
Makefile falls back to PlatformIO's own auto-detection.

## gen_ota_key.sh

Generates the three files required to sign and decrypt OTA firmware images:

- `ota_keys/sign.key.pem` — ECDSA-P256 private key (gitignored, keep secret)
- `ota_keys/sign.pub.pem` — ECDSA-P256 public key (gitignored, embedded in firmware via `gen_eap_certs_asm.py`)
- `ota_keys/aes.key` — 32 raw bytes, AES-256-GCM encryption key (gitignored, embedded in firmware)

The script is idempotent in the safe direction: if any of the three files already
exist it exits with an error rather than overwriting them, preventing accidental
key rotation that would render all previously signed images undeliverable to
fielded devices.  To regenerate, delete the three files explicitly (understanding
that doing so invalidates the current key set for all deployed devices).  After
generation, `sign.key.pem` is chmod 600 and `sign.pub.pem` is chmod 644.  A
sanity check confirms the AES key is exactly 32 bytes and the public key parses
as a prime256v1 curve point.  The `OTA_KEYS_DIR` environment variable overrides
the default output directory (`ota_keys/`), which is used by the test suite to
isolate test keys from project keys.

Requires: `openssl` in PATH.

Usage:
```
bash scripts/gen_ota_key.sh
```

## sign_firmware.py

Signs and encrypts a compiled firmware binary, producing a `.ota` file for
delivery via `ssh ota@<device>`.  The output format is:

```
[8B  magic "ESPOTA1\0"]
[4B  version, LE uint32 = 1]
[4B  plaintext_len, LE uint32]
[12B AES-GCM IV, random]
[16B AES-GCM authentication tag]
[NB  ciphertext, AES-256-GCM encrypted firmware]
[64B ECDSA-P256 signature, raw r||s]
```

The ECDSA signature covers `SHA-256(magic + version + plaintext_len + IV + tag +
ciphertext)`.  The 64-byte signature itself is not included in the signed region.
After writing the output file the script performs a self-test: it re-reads the
file, checks the magic and version fields, and verifies the ECDSA signature,
exiting non-zero if any check fails.

Requires: `python3-cryptography` (`pip install cryptography`).  An `openssl`
subprocess fallback path exists in the code but raises an error at the GCM tag
extraction step because `openssl enc` does not expose the tag; install the Python
package instead.

Usage:
```
# Default paths (ota_keys/sign.key.pem, ota_keys/aes.key):
python3 scripts/sign_firmware.py .pio/build/esp32s3/firmware.bin
# Output: .pio/build/esp32s3/firmware.bin.ota

# Explicit paths:
python3 scripts/sign_firmware.py firmware.bin \
    --key ota_keys/sign.key.pem \
    --aes ota_keys/aes.key \
    --out firmware.ota
```
