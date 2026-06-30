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
| `clean_ds_store.py` | PlatformIO `pre:` hook (all envs) | Strips stray macOS `.DS_Store` files from `managed_components/` before the build |
| `detect_upload_port.sh` | `make flash` (resolves `PORT`) | Finds the CH340 USB-UART bridge by VID for flashing |
| `reboot_to_bootloader.py` | `make flash-online` non-debug path; manual recovery | Sends the CDC RX magic that drops a running non-debug firmware into ROM USB DFU |
| `ota_send.py` | Developer, each OTA release | Streams an encrypted firmware image to a running device over SSH |
| `scep_enroll_zero.py` | Developer (manual) -- Zero provisioning | Host-side SCEP enrollment (PyScep vs. NDES) that writes `main/certs/{ca.pem,client.crt,client.key}` for build-time embedding |
| `test_mdns_build_matrix.sh` | Developer (manual) | Builds the firmware with `MDNS_ENABLE` off then on and checks symbol presence in the ELF |
| `test_ntp_build_matrix.sh` | Developer (manual) | Builds twice over `NTP_ENABLE` and checks `esp_netif_sntp_init` symbol presence |
| `test_ssh_keepalive_build_matrix.sh` | Developer (manual) | Builds three times over `SSH_KEEPALIVE_INTERVAL_SEC` (default / 0 / 5) and checks `wolfSSH_global_request` symbol presence |

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
resolve the correct serial device for `make flash`.  Filters
USB devices by the CH340/CH343 vendor ID (`0x1a86`) so the flashing port is
picked out even when the ESP32-S3's own native USB CDC enumerates with the same
filename pattern.

For Zero-class boards (no CH340) and for `USB_DEBUG_CONSOLE_ONLY` builds on any
board where TinyUSB is absent, the script falls back to detecting the ESP32-S3
USB-Serial-JTAG controller (`303a:1001`).  On the Zero this requires the
BOOT+RESET dance before running `make flash`.  On the DevKitC-1 in debug-console
mode the CH340 (`1a86`) is still detected first (higher priority) and is the
correct port to drive `esptool` against.

## reboot_to_bootloader.py

Standalone recovery helper: sends the USB-CDC magic byte sequence to a
local `/dev/ttyACM*` that is a running esp-tty non-debug firmware.  Use
when Wi-Fi/OTA is unreachable and the BOOT button is physically out of
reach: the magic forces the firmware to reboot into the ROM USB DFU
endpoint (303a:0009), at which point `dfu-util` (or `esptool`) can write a
fresh image without any button presses.

The script deliberately bypasses pyserial and writes via `os.open` /
`os.write`, because pyserial's `Serial.open()` always issues an RTS-line
ioctl that TinyUSB's CDC ACM stack rejects with EPROTO -- the open call
would fail before any bytes reach the device.

Before writing it clears `OPOST` on the port via `termios` (line-discipline
only -- it never touches RTS/DTR, so the EPROTO property above is
preserved).  Without this, a port that a `serial-getty`/`agetty` has left
in cooked mode rewrites the magic's bracketing `\n` to `\r\n`, corrupting
the sequence so the matcher never fires and the trigger silently no-ops.
This is what lets `make flash-online` run while a getty is bound to the
bridge port.

Only useful against non-debug builds: `USB_DEBUG_CONSOLE_ONLY` builds skip
`usb_cdc_init`, so the magic-matcher in
`lib/usb_cdc_boot_trigger/usb_cdc_boot_trigger.c` is never fed.  In a
debug build the chip already enumerates as 303a:1001 and esptool can reset
it directly -- no magic needed.

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
make ota <devname>      # uses main/config.<devname>.h
```

Test hooks (used by the test plan in CLAUDE.md):

- `--tamper` flips a single ciphertext byte before sending, exercising the
  device's auth-tag-failure path.
- `--truncate N` announces the full plaintext length but only sends `N` bytes
  of ciphertext, then closes the channel; verifies the device handles
  truncated transfers without partially flashing the new slot.

## scep_enroll_zero.py

Host-side SCEP enrollment helper for provisioning a Mode B+ device whose
board is too small to run the SCEP state machine at runtime (e.g. the
ESP32-S3-Zero).  It drives a full enrollment against real Microsoft NDES
from the developer's machine using PyScep, then writes the issued
`ca.pem`, `client.crt`, and `client.key` into `main/certs/` so the next
build embeds them directly -- no runtime SCEP, no on-device cert storage.

Manual and developer-run (not wired into the build).  The script also
monkey-patches two bugs in PyScep 0.0.14 -- a `_filter` CA-selection bug
and an EC-key signature-verification arity mismatch; see the comments at
the top of the file for details.

## Build-flag matrix scripts

`test_mdns_build_matrix.sh`, `test_ntp_build_matrix.sh`, and
`test_ssh_keepalive_build_matrix.sh` each build the firmware multiple times
under different compile-time flag combinations and use `xtensa-esp32s3-elf-nm`
to confirm that the relevant ESP-IDF / wolfSSH symbols appear (or do not
appear) in the resulting ELF. They are developer-run manual smoke tests --
not wired into PlatformIO or pytest -- and each takes a few minutes since
they invoke a full `pio run` per case. Each script patches `main/config.h`
in place and restores the original on exit.
