# esp-tty — Nano Console Server

ESP32-S3 SSH-over-WiFi bridge to USB CDC ACM.

## What this is

The nano console server is a small device that sits between a target board and
your laptop. The target board (Arduino, ESP32, RP2040, Linux SBC, or anything
with a USB serial port) plugs into the ESP32-S3 via a USB-C cable. The ESP32-S3
exposes that serial connection as an authenticated SSH session over Wi-Fi on port
2222. Instead of running a UART dongle cable to your workstation and opening a
terminal emulator, you SSH in from anywhere on the network.

The device supports a single concurrent SSH session and public-key authentication
only. When a second client connects while a session is active, the old session is
torn down and the new one takes over. This is intentional: the serial console of
a target board is a single shared resource.

OTA firmware updates are delivered over the same SSH interface by authenticating
as the `ota` user. Update images are signed with ECDSA-P256 and encrypted with
AES-256-GCM; the device verifies the signature and authentication tag before
switching the boot partition.

## Hardware

Target: **ESP32-S3-DevKitC-1 N16R8** (16 MB quad-IO flash, 8 MB OPI PSRAM).

Other ESP32-S3 modules can be used but will require changes to:
- `partitions.csv` (the current table assumes 16 MB flash with 4 MB OTA
  partitions)
- `platformio.ini` (`board_upload.flash_size`, `board_upload.maximum_size`,
  `board_build.arduino.memory_type`)

The 8 MB PSRAM is used for the ring buffers. Devices without PSRAM would need
the ring buffers moved to internal SRAM and the ring size reduced significantly.

## Features

- WPA2/WPA3-Personal Wi-Fi (PSK). WPA2/WPA3-Enterprise EAP-TLS is opt-in via
  `#define WIFI_USE_ENTERPRISE` in `config.h` (see `main/certs/README.md` for
  certificate setup).
- wolfSSH server on TCP/2222 with hardware-accelerated AES-256-GCM and
  SHA-256/512 via the ESP32-S3 AES and SHA peripherals (wolfSSL Espressif port).
- Ed25519 host key generated on first boot and stored in encrypted NVS.
  Fingerprint printed to UART on every boot.
- Public-key-only authentication. Two enforced usernames:
  - `tty@<device>` — for serial console sessions; the firmware accepts up to
    8 authorized keys defined as a comma-separated list in `AUTHORIZED_PUBKEYS`
    (see `config.h.example`).
  - `ota@<device>` — for OTA firmware updates; single authorized key in
    `OTA_AUTHORIZED_PUBKEY`.
  Any other username is rejected before the key is even checked.
- Running at **240 MHz** with `-O2` for production builds (~1.5× faster than
  the IDF default 160 MHz / `-Og`).
- Encrypted NVS using AES-XTS-256 with the key stored in the `nvs_keys`
  partition. No eFuses are burned.
- Signed and encrypted OTA updates over SSH: ECDSA-P256 signature + AES-256-GCM
  encryption, A/B partition scheme with automatic bootloader rollback if the new
  firmware does not call `mark_app_valid_cancel_rollback` within 30 seconds.
- USB CDC ACM bridged to the SSH data stream via two 16 KB FreeRTOS StreamBuffer
  ring buffers in PSRAM.
- Single-session takeover with semaphore-based synchronisation to prevent
  use-after-free races on wolfSSH objects when the pump tasks exit.
- Cipher hardening: AES-CBC, AES-192, SHA-1 MAC, and DH key exchange are all
  disabled at compile time via `wolfssh_options.h`.

## Security model

Authentication is public-key only. The authorized public keys are compiled into
the firmware from `config.h`; they are not stored in NVS and cannot be changed
without a firmware update.

The threat model addresses a network attacker. A physical attacker who can dump
the SPI flash can extract the `nvs_keys` partition, which contains the AES-XTS-256
key used to encrypt NVS. With that key, the attacker can decrypt the NVS and
retrieve the Ed25519 host key. They cannot retrieve the authorized public keys
(those are in firmware flash, not NVS) and they cannot sign new OTA images
without the ECDSA-P256 private key (`ota_keys/sign.key.pem`), which is never
stored on the device.

No eFuses are burned. SPI flash encryption (which would close the physical
extraction gap) burns eFuses and makes the device permanently locked; this is
outside the scope of a development tool that must remain reflashable.

Hardware acceleration on ESP32-S3:
- AES: hardware AES peripheral via `esp32_aes.c` (ESP-IDF HW crypto layer). Used
  for AES-256-GCM ciphertext encryption/decryption in SSH and OTA.
- SHA: hardware SHA peripheral via `esp32_sha.c`. Used for SHA-256 and SHA-512
  in SSH handshake and fingerprint computation.
- MPI/bignum: hardware MPI accelerator is used for ECDSA P-256 and P-384 bignum
  operations (modular multiplication, modular exponentiation).

Software only (no hardware unit on this silicon):
- Ed25519 / X25519 curve operations. ESP32-S3 has no curve-25519 hardware; these
  run in wolfSSL's optimized C implementation.
- AES-GCM GHASH (the authentication tag computation). GHASH is computed in
  software; only the AES block cipher itself uses hardware.

## Quick start

### 1. Configure credentials

```
cp main/config.h.example main/config.h
# Edit with your values:
#   WIFI_SSID              — your network SSID
#   WIFI_PASS              — your WPA2/WPA3-Personal passphrase
#   AUTHORIZED_PUBKEYS     — comma-separated list of ~/.ssh/id_ed25519.pub
#                            contents (up to 8 keys; any matches succeeds)
#   OTA_AUTHORIZED_PUBKEY  — a public key for OTA deploys (can be the same key)
```

### 2. Generate OTA signing keys

```
bash scripts/gen_ota_key.sh
```

This creates `ota_keys/sign.key.pem`, `ota_keys/sign.pub.pem`, and
`ota_keys/aes.key`. All three are gitignored. Back them up in a secure location;
if lost, you cannot sign new OTA firmware for devices running the current
firmware.

### 3. Build and flash

```
make build     # compile firmware
make flash     # compile + flash to the device (or just: make)
```

The `Makefile` is a thin wrapper around PlatformIO. It auto-detects a
CH340/CH343 USB-UART bridge (the typical ESP32-S3 flash port) so the
upload doesn't accidentally target the device's own USB-CDC port. To
override:

```
make flash PORT=/dev/ttyUSB0
```

The underlying PlatformIO commands still work too: `pio run -e esp32s3`
and `pio run -e esp32s3 --target upload`.

### 4. Find the device IP

```
pio device monitor
```

Watch for the IP address and host key fingerprint printed at boot:

```
I (1234) wifi: Connected, IP: 192.168.1.42
I (1235) host_key: Host key SHA-256 fingerprint: 8b:2e:eb:84:...
I (1236) ssh_server: Listening on TCP port 2222
```

### 5. Connect

```
ssh -p 2222 tty@192.168.1.42
```

Verify the fingerprint against what was printed to UART on first boot.

The username **must be `tty`** for a console session (or `ota` for an OTA
upload); any other username is rejected.

### 6. Linux host setup (on the box the device plugs into)

The ESP32-S3 enumerates as a USB CDC device at `/dev/ttyACM0`. To expose a
shell on it (so SSH'ing into the device gives you a login on that host),
enable the stock systemd serial-getty:

```
systemctl enable --now serial-getty@ttyACM0.service
```

That's it — no drop-ins, no `TERM=` overrides, no agetty flags. The default
invocation works because the firmware fully drains the USB CDC RX FIFO per
callback, so `agetty` writes never stall mid-banner.

## OTA usage

Sign a compiled firmware binary:

```
python3 scripts/sign_firmware.py .pio/build/esp32s3/firmware.bin
# Produces: .pio/build/esp32s3/firmware.bin.ota
```

Upload via SSH:

```
ssh -i ~/.ssh/ota_key -p 2222 ota@192.168.1.42 < .pio/build/esp32s3/firmware.bin.ota
```

The device verifies the ECDSA signature and AES-GCM authentication tag, writes
the new firmware to the inactive OTA partition, switches the boot partition, and
reboots. If the new firmware crashes or the watchdog fires before the 30-second
rollback timer fires, the bootloader automatically reverts to the previous image.

If the signature or tag verification fails, the device closes the SSH session
and continues running the existing firmware. The boot partition is never changed
on a failed verification.

## Architecture

### Data path

```
Target board <-USB-C-> ESP32-S3 (TinyUSB CDC ACM)
                              |
                    [usb_to_ssh ring, 16 KB PSRAM]
                              |
                    wolfSSH session (TCP/2222)
                              |
                    [ssh_to_usb ring, 16 KB PSRAM]
                              |
               ESP32-S3 (TinyUSB CDC ACM) <-USB-C-> Target board
```

Four concurrent actors:

| Actor | Role |
|---|---|
| `ssh_server_task` | wolfSSH accept loop, auth dispatch, session teardown |
| `usb_tx_task` | Drains `ssh_to_usb` ring into TinyUSB CDC TX |
| TinyUSB internal task | CDC RX callback pushes bytes into `usb_to_ssh` ring |
| `rollback_timer_cb` | Fires 30 s after boot; marks OTA image valid |

### OTA path

```
ssh client           ESP32-S3
    |                    |
    |-- SSH channel ---> ota_session_run()
    |                    |-- ota_verify_begin()
    |-- stream data ---> |-- ota_verify_feed()  [writes to OTA partition]
    |                    |-- ota_verify_end()
    |                         ECDSA verify OK?
    |                           yes: esp_ota_set_boot_partition() + esp_restart()
    |                           no:  esp_ota_abort() + SSH error message
```

## Project layout

```
esp-tty/
  main/               Application source (ssh_server, ota_session, wifi, usb_cdc)
                      See main/README.md
  lib/                Shared libraries: ring, bridge, pubkey_auth, ota_verify,
                        ota_stream, rollback_decision, scrollback,
                        usb_cdc_drain, term_resize
                      See lib/README.md
  components/         Local wolfSSL bridge IDF component
                      See components/README.md
  scripts/            Key generation, firmware signing, and build hooks
                      See scripts/README.md
  patches/            Patches applied to managed_components/ at build time
                      See patches/README.md
  test/
    native/           Native unit test suites (no hardware)
    scripts/          Integration and system test runners
                      See test/scripts/README.md
    stubs/            OpenSSL-backed wolfCrypt and mbedtls stubs for native tests
                      See test/stubs/README.md
    wokwi/            Wokwi simulator configuration
                      See test/wokwi/README.md
    README.md         Test suite overview and coverage gaps
  ota_keys/           OTA signing keys (gitignored except .example files)
                      See ota_keys/README.md
  main/certs/         EAP-TLS certificates (gitignored except .example files)
                      See main/certs/README.md
  partitions.csv      16 MB A/B OTA partition table
  platformio.ini      Build environment definitions
  sdkconfig.defaults  Base sdkconfig overrides (applied to all envs)
  sdkconfig.esp32s3   Hardware-target sdkconfig overrides
  sdkconfig.wokwi     Wokwi simulator sdkconfig overrides
```

## Build environments

Three PlatformIO environments are defined in `platformio.ini`:

### esp32s3 (default)

Builds for real ESP32-S3-DevKitC-1 N16R8 hardware. Uses ESP-IDF 5.4.1
(pinned via `espressif32@6.11.0`). Hardware crypto enabled.

```
pio run -e esp32s3
pio run -e esp32s3 --target upload
```

### wokwi

Same firmware as `esp32s3` but compiled with `BRIDGE_LOOPBACK=1`. This flag
bypasses TinyUSB CDC ACM and wires the two ring buffers directly together,
making the firmware compatible with the Wokwi simulator and `qemu-system-xtensa`
(neither of which emulates USB CDC host enumeration). Used by the QEMU smoke
tests.

```
pio run -e wokwi
```

### native

Host unit tests. Compiles only the libraries in `lib/` against the OpenSSL-backed
stubs in `test/stubs/`. No ESP-IDF, no wolfSSH, no hardware. Runs on Linux and
macOS.

```
pio test -e native
```

## Testing

### Native unit tests — 155 test cases

Run on the host without any hardware or emulator. See `test/README.md` for the
per-suite breakdown.

| Suite | Cases |
|---|---|
| test_ring | 17 |
| test_bridge | 5 |
| test_bridge_scrollback | 4 |
| test_cdc_drain | 6 |
| test_term_resize | 10 |
| test_scrollback | 26 |
| test_ota_stream | 7 |
| test_pubkey_auth | 12 |
| test_host_key | 9 |
| test_auth_check | 10 |
| test_user_class | 23 |
| test_ota_verify | 20 |
| test_rollback_decision | 6 |

```
pio test -e native
```

### QEMU smoke test

Builds the wokwi firmware, merges a 16 MB flash image, boots under
`qemu-system-xtensa` (Espressif fork), and asserts:
- NVS encryption key is generated on first boot
- Ed25519 host key SHA-256 fingerprint is printed in the correct format
- SSH server starts and listens on port 2222

```
python3 test/scripts/test_qemu_boot.py
```

### QEMU NVS persistence test

Two-boot test: asserts the host key write path works on boot 1 and the SSH
server starts on boot 2. Fingerprint equality between boots is not asserted due
to a QEMU nvs_keys emulation limitation (documented in
`test/scripts/test_qemu_nvs_persistence.py`).

```
python3 test/scripts/test_qemu_nvs_persistence.py
```

### OTA signer roundtrip test

Generates temporary keys, signs a dummy firmware on the host, and verifies it
using the `ota_verify` library compiled natively. Also tests the tamper-detection
and empty-firmware-rejection paths.

```
bash test/scripts/test_ota_signer_roundtrip.sh
```

### Other integration tests

```
bash test/scripts/test_clean_build.sh   # clean build reproducibility
bash test/scripts/test_gen_ota_key.sh   # gen_ota_key.sh correctness
python3 test/scripts/test_apply_patches.py  # patch application logic
```

### Known gaps

The following are not covered by any automated test and require real hardware or
deep mocking that has not been done:

- `host_key.c` — key generation and NVS write/read path (needs wolfCrypt RNG
  and NVS flash emulation). Only `format_fingerprint` is tested natively.
- `wifi.c` — event handlers and reconnect logic (requires a FreeRTOS event loop).
- `usb_cdc.c` — TinyUSB RX/TX callbacks (could be mocked but has not been).
- `ssh_server.c` — accept loop, session takeover, bridge pump tasks (requires
  wolfSSH and a live TCP connection).
- Full E2E SSH session: `qemu-system-xtensa` for ESP32-S3 has no NIC emulation
  the firmware can drive. A live SSH connection test requires real hardware.
- WPA2/WPA3-Enterprise EAP-TLS path: compiled and structurally tested in the
  clean-build test, but never connected to a real RADIUS server.

## Dependencies

| Dependency | Version / source |
|---|---|
| PlatformIO Core | Current stable |
| ESP-IDF | 5.4.1 LTS (pinned via `espressif32@6.11.0`) |
| wolfSSL | 5.8.2~1 (IDF component manager, `wolfssl/wolfssl`) |
| wolfSSH | 1.4.20 (IDF component manager, `wolfssl/wolfssh`) |
| mbedtls | Built into ESP-IDF; hardware-accelerated on S3 |
| TinyUSB | Built into ESP-IDF |
| QEMU Espressif fork | `esp_develop_9.2.2_20250817` (optional, for QEMU tests) |
| openssl | System openssl (for key generation and native test stubs) |
| python3-cryptography | `pip install cryptography` (for `sign_firmware.py`) |

## Known limitations and future work

- Single concurrent SSH session (by design — the serial console is a single
  shared resource; no queueing or multiplexing is planned).
- No mDNS or Bonjour. Device IP discovery is via the UART boot log only. mDNS
  is planned but not implemented.
- No GPIO control of the target board's reset or boot-mode pins. Adding a relay
  or transistor control over SSH is planned.
- Wi-Fi event handler reconnect logic has not been exercised under real
  disconnect conditions. It is implemented but hardware-only.
- WPA2/WPA3-Enterprise EAP-TLS is compiled in and structurally correct but has
  not been tested against a real RADIUS server. Certificate time validation
  requires SNTP sync at boot (see `main/certs/README.md`).
- QEMU NVS persistence test cannot assert fingerprint equality across boots due
  to the QEMU nvs_keys emulation limitation (see
  `test/scripts/test_qemu_nvs_persistence.py` for details). This is a QEMU
  limitation, not a firmware issue.

## Contributing

Before submitting changes:

1. Run `pio test -e native` — all 73 test cases must pass.
2. Run `python3 test/scripts/test_qemu_boot.py` — the smoke test must pass.
3. If you modified `lib/ota_verify` or `scripts/sign_firmware.py`, also run
   `bash test/scripts/test_ota_signer_roundtrip.sh`.

---

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

If you run a modified version of this firmware on a device that interacts with
users over a network (e.g. an SSH server reachable beyond your own machines),
the AGPL requires you to make the corresponding source available to those
users. The full license text is in [LICENSE](LICENSE).

This project bundles managed components under their own licenses:
wolfSSL/wolfSSH (GPL-2.0-or-later or commercial), mbedtls (Apache-2.0),
TinyUSB (MIT), ESP-IDF (Apache-2.0). See each component's own COPYING /
LICENSE file under `managed_components/` after a build.
