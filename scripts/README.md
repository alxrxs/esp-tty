# scripts/ -- Build and OTA Utilities

This directory contains the build-system hooks and developer utilities for the
esp-tty firmware project.  All scripts are designed to be idempotent or to fail
loudly rather than silently corrupt state.

| Script | When it runs | Purpose |
|---|---|---|
| `fetch_managed_components.py` | PlatformIO `pre:` hook | Populates `managed_components/` before cmake runs |
| `gen_eap_certs_asm.py` | PlatformIO `post:` hook | Pre-generates EAP-TLS cert `.S` assembly files |
| `apply_managed_patches_cmake.py` | CMake configure step | Applies `patches/` to `managed_components/` |
| `apply_managed_patches.py` | (not wired; reference only) | Alternate SCons entry point for the same patch logic |
| `detect_upload_port.sh` | `make flash` / `make monitor` | Finds the CH340 USB-UART bridge by VID for flashing |
| `ota_send.py` | Developer, each OTA release | Streams an encrypted firmware image to a running device over SSH |

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

PlatformIO `extra_scripts = post:scripts/gen_eap_certs_asm.py` hook.  It works
around a PlatformIO/ESP-IDF scheduling conflict: ESP-IDF marks the EAP-TLS
certificate files (`ca.pem.S`, `client.crt.S`, `client.key.S`) as generated
sources in the cmake codemodel, but PlatformIO replaces the ninja build with
its own SCons graph and never invokes the cmake custom command that would
create those `.S` files.  On a clean build the files do not exist when SCons
tries to assemble them, causing an immediate build failure.

The hook fixes this by invoking ESP-IDF's `data_file_embed_asm.cmake` script
directly at PlatformIO script-evaluation time -- before SCons has read the build
graph -- writing the `.S` files into `BUILD_DIR` exactly where the cmake
codemodel says they live.  The hook is a no-op if the certificate source files
are absent.

## apply_managed_patches_cmake.py

Called by the root `CMakeLists.txt` via `execute_process` during the cmake
configure step.  Scans `patches/<component>/*.patch` and applies each patch to
the matching `managed_components/<component>/` tree, using `patch --dry-run -R`
to short-circuit when a patch is already present (so re-runs are idempotent).

## apply_managed_patches.py

Alternative SCons-side entry point for the same patching logic.  Not wired into
`platformio.ini` in the current build; retained for reference.

## detect_upload_port.sh

Called by the `Makefile` (`PORT ?= $(shell scripts/detect_upload_port.sh)`) to
resolve the correct serial device for `make flash` and `make monitor`.  Filters
USB devices by the CH340/CH343 vendor ID (`0x1a86`) so the flashing port is
picked out even when the ESP32-S3's own native USB CDC enumerates with the same
filename pattern.

## ota_send.py

Uploads a compiled firmware binary to a running device over an SSH
`ota@<host>` session.

The script opens a paramiko SSH connection (authentication delegated to the
caller's SSH agent / `~/.ssh/config`), then performs an ephemeral X25519 key
exchange inside the SSH channel and derives a per-upload AES-256-GCM key with
HKDF-SHA256.  The firmware is encrypted in memory and streamed to the device,
which decrypts it into the inactive OTA partition and reboots.  No
pre-shared OTA key material is needed -- the only credential is the SSH key
that matches `OTA_AUTHORIZED_PUBKEY` in the device firmware.

Wire protocol (matches `main/ota_session.c`):

```
device -> [0x02] [32B device_ephemeral_x25519_pub]
client -> [32B client_ephemeral_x25519_pub]
client -> [4B plaintext_len LE] [12B IV] [16B GCM tag] [N B ciphertext]
device -> 0x00                       (success, rebooting)
       or 0xFF + "<reason>\n"        (failure, no reboot)
```

Requires: `paramiko`, `cryptography` (both installed by `requirements.txt`).

Usage:
```
.venv/bin/python scripts/ota_send.py <host> .pio/build/esp32s3/firmware.bin
# or, via the Makefile wrapper:
make ota <host>
make ota <devname>      # uses main/config.h.<devname>
```

Test hooks (used by the test plan in CLAUDE.md):

- `--tamper` flips a single ciphertext byte before sending, exercising the
  device's auth-tag-failure path.
- `--truncate N` announces the full plaintext length but only sends `N` bytes
  of ciphertext, then closes the channel; verifies the device handles
  truncated transfers without partially flashing the new slot.
