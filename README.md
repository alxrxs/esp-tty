# esp-tty -- Nano Console Server

Wireless out-of-band serial console for a Linux server you don't want to
lose access to.

When the server's primary network is unreachable -- bad netplan, locked-out
firewall rule, NIC carrier loss, mis-pulled cable, switch failure on the
management VLAN -- you reach it through this device. Plug the ESP32-S3
DevKit into a free USB port on the server. The server sees a virtual serial
port (the ESP32-S3's TinyUSB CDC ACM endpoint) and runs `agetty` on it just
like a hardware serial console. SSH into the ESP32-S3 over Wi-Fi: you're at
the server's login prompt over a network path that has nothing to do with
the server's main NIC.

```mermaid
flowchart LR
    target["Linux server<br/>(USB-serial)"] -- "USB-C" --> esp["ESP32-S3"] -- "Wi-Fi" --> ssh["SSH client"]
```

Server-side requirements: a Linux/BSD/macOS kernel with USB host support
and `agetty` (or equivalent) bound to the resulting `/dev/ttyACM*` node.

One SSH session is active at a time; opening a second one preempts the
first within ~200 ms. Public-key authentication only. The username `tty`
selects an interactive console; the username `ota` accepts a signed and
encrypted firmware update over the same SSH channel. Any other username
is rejected before any key material is inspected.

## Contents

- [Features](#features)
- [Hardware](#hardware)
- [Dependencies](#dependencies)
- [Quick start](#quick-start)
- [Server-side getty](#server-side-getty)
- [Configuration](#configuration)
- [Building & testing](#building--testing)
- [Flashing & recovery](#flashing--recovery)
- [OTA updates](#ota-updates)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Repository layout](#repository-layout)
- [Scope](#scope)
- [License](#license)

## Features

- TinyUSB CDC ACM bridge to wolfSSH over Wi-Fi, two 16 KB PSRAM ring
  buffers in between, TCP 22 by default.
- 128 KB scrollback captured even when no SSH client is connected; the
  last 1000 lines are replayed on each new session.
- Up to 8 ED25519 keys for `tty@` (`AUTHORIZED_PUBKEYS`), one separate
  key for `ota@` (`OTA_AUTHORIZED_PUBKEY`).
- ED25519 host key generated on first boot, stored in AES-XTS-256-encrypted
  NVS. Fingerprint printed at every boot.
- Encrypted OTA: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM, authenticated
  via the SSH login on `ota@`, A/B partition layout, automatic rollback if
  the new image fails its self-test.
- Three Wi-Fi modes: WPA2/WPA3-Personal (Mode A), WPA2/WPA3-Enterprise
  EAP-TLS with embedded certs (Mode B), or SCEP auto-enrollment against a
  Microsoft NDES CA with background renewal (Mode C).
- Hardware-accelerated crypto on the ESP32-S3 SHA/AES peripherals via the
  wolfSSL Espressif port; mbedTLS used for X.509, PKCS#7/PKCS#10, and the
  HTTPS path to the SCEP server. AES-256-GCM is the only SSH cipher
  offered; `aes256-gcm@openssh.com` is pinned at runtime.
- Off-grid defaults: unlimited Wi-Fi reconnect, DHCP watchdog that re-kicks
  the client if no lease arrives.
- Per-device config workflow: `make flash <devname>` switches the active
  config via a symlink, `make ota <devname>` builds and uploads to the IP
  recorded in that config file.
- Extensive native Unity + pytest coverage; runs on the host without any
  ESP32 hardware or emulator.

## Hardware

Two boards are supported out of the box:

| | ESP32-S3-DevKitC-1 N16R8 | Waveshare ESP32-S3-Zero |
|---|---|---|
| PlatformIO env | `esp32s3` (default) | `esp32s3_zero` |
| Flash | 16 MB QIO external | 4 MB QIO embedded (FH4R2) |
| PSRAM | 8 MB OPI (Octal) | 2 MB QSPI (Quad, embedded) |
| OTA slot size | 4 MB each | ~1.94 MB each |
| USB | CH340 UART + native USB | Native USB only |
| Auto-reset | Yes | No -- hold BOOT, tap RESET |
| Boot log | CH340 → `/dev/ttyACM0` | UART0 on GPIO43/44 pads |
| Form factor | 51 × 28 mm devkit | 22 × 18 mm stamp module |

The Zero is a good fit when size matters. The trade-offs are tighter OTA
slots (~1.94 MB vs 4 MB), no USB-UART bridge (debug logs require an
external USB-UART dongle clipped to GPIO43/44), and manual boot-mode entry
for flashing (no transistor auto-reset circuit). The board-specific
flashing steps are covered under [Flashing & recovery](#flashing--recovery).

### DevKitC-1 USB interfaces

The DevKitC exposes two USB interfaces on the same cable:

| USB VID:PID | Device node | What it is |
|---|---|---|
| `1a86:55d3` | `ttyACM*` | CH340 USB-UART -- ESP-IDF boot log and flash port |
| `303a:xxxx` | `ttyACM*` | esp-tty TinyUSB CDC -- the SSH bridge data path |

The TinyUSB PID is whatever you set as `USB_PID` in `config.h`. Node
numbers shift if other ACM devices are present; identify the bridge by
VID:PID, not by filename. The full VID:PID-by-chip-state table is under
[Flashing & recovery](#usb-vidpid-by-chip-state).

The DevKitC has the standard auto-reset wiring: DTR drives IO0, RTS drives
EN. Opening the CH340 port with default termios asserts both, which the
circuit interprets as a reset pulse -- so `cat /dev/ttyACM0` reboots the
chip. Use `picocom --noreset`, `pio device monitor`, or pyserial with
`setRTS(False) / setDTR(False)` to read the console without resetting.
`make flash` drives this circuit on purpose and works reliably.

## Dependencies

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

That installs PlatformIO, `paramiko`, and `cryptography` (the latter two
used by `scripts/ota_send.py`). PlatformIO pulls in ESP-IDF 5.4.1 LTS via
`espressif32@6.11.0` on first run. wolfSSL and wolfSSH are fetched by
the IDF component manager at cmake configure time.

System tools (not pip-installable):

| Tool | Used by |
|---|---|
| `openssl` | EAP-TLS cert generation (Mode B) |
| `qemu-system-xtensa` (Espressif fork) | QEMU smoke tests |
| `patch` | applying `patches/*.patch` at cmake configure |
| `dfu-util` + `usbutils` | `make flash-online` (USB DFU reflash) |

## Quick start

```
git clone <repo-url> && cd esp-tty
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

cp main/config.example.h main/config.h
$EDITOR main/config.h     # required: WIFI_SSID, WIFI_PASS, AUTHORIZED_PUBKEYS.
                          # Add OTA_AUTHORIZED_PUBKEY to enable OTA updates.

make flash      # build + flash (auto-detects the CH340 port)
```

(See [Dependencies](#dependencies) for the full toolchain list and
[Configuration](#configuration) for everything `config.h` controls.)

Find the device IP and host-key fingerprint in the UART boot log
(`pio device monitor`):

```
I (1099) wifi: DHCP hostname: esp-tty
I (1203) wifi: Wi-Fi MAC: 1c:db:d4:74:a1:fc
I (5026) wifi: IP address : 192.168.1.42
I (5037) host_key: Host key SHA-256 fingerprint: 88:e0:a6:58:...
I (5079) ssh_server: Listening on TCP port 22
```

Connect to that IP:

```
ssh tty@192.168.1.42
```

Define `MDNS_ENABLE` in `config.h` to reach the device by name
(`ssh tty@esp-tty.local`) via any mDNS-aware resolver.

SSH only hands you the raw serial line; for the target to present a login
prompt on it, the **target server** must run `agetty` on the bridge port --
see [Server-side getty](#server-side-getty).

## Server-side getty

This runs on the **target server** -- the machine whose console you want to
reach. It binds a login prompt to the CDC bridge port the ESP32-S3 presents.

Match the bridge port reliably by VID:PID:

```
ls -l /dev/serial/by-id/ | grep '303a'
```

Or pin a stable symlink with a udev rule (substitute your `USB_PID`):

```
# /etc/udev/rules.d/99-esp-tty.rules
SUBSYSTEM=="tty", ATTRS{idVendor}=="303a", ATTRS{idProduct}=="4001", SYMLINK+="ttyESPTTY"
```

Enable getty on the bridge port:

```
systemctl enable --now serial-getty@ttyACM1.service
```

The stock unit has `Restart=always` but systemd's default rate-limit
(`StartLimitBurst=5 / StartLimitIntervalSec=10`) makes it give up after a
handful of fast restarts. Every time the ESP32-S3 reboots (OTA, brief power
glitch, USB hub hiccup), the CDC node re-enumerates and getty restarts; on
a flapping link that's easy to exceed. Disable the rate-limit:

```
sudo mkdir -p /etc/systemd/system/serial-getty@ttyACM1.service.d
sudo tee /etc/systemd/system/serial-getty@ttyACM1.service.d/restart-limits.conf <<'EOF'
[Service]
RestartSec=2
StartLimitIntervalSec=0
EOF
sudo systemctl daemon-reload
sudo systemctl restart serial-getty@ttyACM1.service
```

## Configuration

All build-time configuration lives in `main/config.h`, copied from
`main/config.example.h`. `config.h` itself is gitignored. The required
minimum is `WIFI_SSID`, `WIFI_PASS`, and `AUTHORIZED_PUBKEYS`; everything
else has a default. Define `OTA_AUTHORIZED_PUBKEY` as well if you want OTA
updates -- omitting it simply disables the `ota@` login.

`AUTHORIZED_PUBKEYS` is a comma-separated list of OpenSSH ED25519 public
keys (`"ssh-ed25519 AAAA... user@host"`, up to 8) -- generate one with
`ssh-keygen -t ed25519` and paste the line from the resulting `.pub` file.
`OTA_AUTHORIZED_PUBKEY` is a single key of the same form.

`config.example.h` is the authoritative reference for every option,
including ones this README doesn't drill into: IPv6 addressing, static
IPv4, NTP servers, Wi-Fi country / TX-power, and the assorted
timeout/retry tunables.

### Per-device configuration

To manage several devices from one checkout, keep a
`main/config.<devname>.h` per device. `make flash <devname>` and
`make ota <devname>` symlink `main/config.h -> config.<devname>.h`, then
build. Because `config.h` is a symlink, in-place edits flow through to the
underlying `config.<devname>.h` -- no separate "save" step. Switching
devices just repoints the symlink.

The first line of each per-device config is a `//` comment marker the
Makefile reads to find the OTA target:

```c
// MAKE-OTA-IP: 10.57.99.42
#pragma once
#define WIFI_SSID "..."
// ...
```

- `MAKE-OTA-IP` -- consumed by `make ota <dev>`. IPv4 / IPv6 / DNS name; any
  string `ssh` can resolve. Omit it if OTA is not used for that device.
  `config.example.h` shows the marker.

Argument resolution:

```
make flash alpha            # symlinks config.h -> config.alpha.h, then flashes
make ota   alpha            # symlinks, then OTAs to that file's MAKE-OTA-IP
make ota   192.168.1.42     # arg isn't a config.<name>.h file -> build current config.h, OTA to IP
make build                  # uses current config.h unchanged
```

`make ota <ip-or-host>` (any argument that doesn't match a
`config.<name>.h` file) builds the current `config.h` as-is and uploads to
that destination.

### Wi-Fi modes

Each mode is selected by which macros you define in `config.h`. The
modes are mutually exclusive.

| Mode | Trigger | Auth | Notes |
|---|---|---|---|
| **A** | `WIFI_SSID` + `WIFI_PASS` | WPA2/WPA3-Personal (PSK) | One network |
| **B** | + `WIFI_USE_ENTERPRISE` | WPA2/WPA3-Enterprise EAP-TLS | One network; client cert + key embedded from `main/certs/` at build time |
| **B+** | + `WIFI_USE_ENTERPRISE` + `WIFI_ENTERPRISE_SSID` | PSK bootstrap for NTP, then WPA3-Enterprise EAP-TLS | Two SSIDs; same embedded certs as Mode B; add `NTP_ENABLE` to sync the clock before EAP-TLS so cert NotBefore/After is validated correctly on cold boot |
| **C** | + `WIFI_ENTERPRISE_SSID` + `SCEP_URL` + `SCEP_CHALLENGE_PASSWORD` | PSK bootstrap, then WPA3-Enterprise EAP-TLS | Two SSIDs; client cert auto-enrolled via SCEP and stored in encrypted NVS |

All three EAP-TLS modes (B, B+, C) read `EAP_IDENTITY`, the inner identity
presented inside the TLS tunnel (the cert-subject identity); it defaults
to `"anonymous"` if unset. For production, also define
`EAP_ANONYMOUS_IDENTITY` -- the outer identity sent in cleartext during
EAP phase 1 (e.g. `"anonymous@example.org"`). It keeps the real
`EAP_IDENTITY` from leaking before the tunnel is up, and NAI-realm routing
on the RADIUS side keys off it.

Mode B and Mode B+ place their three PEMs (`ca.pem`, `client.crt`,
`client.key`) in `main/certs/`; the build embeds them. See
[`main/certs/README.md`](main/certs/README.md).

Mode B+ and Mode C use two distinct SSIDs because IEEE 802.11 ties each
SSID to one auth mode at the AP. In Mode B+ the bootstrap PSK network is
used only for NTP sync; production traffic uses the enterprise SSID.
In Mode C the bootstrap PSK network is additionally used for SCEP enrollment
and renewals when the enterprise side is unreachable.

### SCEP auto-enrollment (Mode C)

RFC 8894 SCEP, tested against Microsoft NDES in legacy CryptoAPI/CSP mode.
Keys are RSA-2048 with SHA-256 PKCS#1 v1.5 signatures (NDES rejects ECDSA
in that mode). The state machine lives in `lib/wifi_state/`; cert storage
in `lib/cred_store/`; protocol encoding in `lib/scep_proto/`; HTTPS
transport in `lib/scep_transport/`.

The ESP32-S3 has no battery-backed RTC -- on a cold boot `time(NULL)`
returns 0, so cert validity comparisons are meaningless until the clock
is synced. Each boot, the state machine picks one of three paths:

| Path | When | Action |
|---|---|---|
| **ENTERPRISE** | Cert in NVS; clock synced + valid, or `EAP_DISABLE_TIME_CHECK` set | Join `WIFI_ENTERPRISE_SSID` via EAP-TLS |
| **BOOTSTRAP_NTP_ONLY** | Cert in NVS; `NTP_BEFORE_EAPTLS` set; clock not synced | Join `WIFI_SSID` (PSK), sync NTP only, loop back to ENTERPRISE |
| **BOOTSTRAP_FULL** | No cert, cert known-expired, or too many EAP-TLS failures (`WIFI_ENTERPRISE_RETRY_MAX`) | Join `WIFI_SSID` (PSK), sync NTP, run SCEP, store the new cert, reboot |

Bootstrap PSK always uses DHCP regardless of `USE_STATIC_IPV4`. Static addressing applies only on the enterprise network.

A successful SCEP exchange against real NDES takes ~9 s end-to-end
(RSA-2048 keygen dominates).

After enrollment, the `cert_renewer` background task wakes every
`CERT_RENEWAL_CHECK_INTERVAL_SEC` seconds and re-enrolls when fewer than
`CERT_RENEWAL_WINDOW_DAYS` remain to expiry. Renewals run over the
enterprise network -- no PSK detour required.

#### No-NTP variant

`SCEP_NO_NTP_USE_ISSUANCE_TIME` covers air-gapped deployments with no
NTP source. Every boot takes the BOOTSTRAP_FULL path and applies the
issued cert's X.509 NotBefore as the local-clock anchor via
`settimeofday()`. The CA's clock becomes the authoritative time source.
The `cert_renewer` task is disabled -- each reboot is the renewal.
Mutually exclusive with `NTP_BEFORE_EAPTLS`; defining both is a
compile-time error.

Trade-offs: every boot burns one NDES challenge password and ~9 s; the
clock anchor is only as accurate as the CA's clock at signing time.

#### NDES CA trust

Place the CA chain PEM in `main/certs/scep_ca.pem`. It must contain the
root CA that signed the NDES server's TLS certificate (not necessarily
the CA that signs device certs). The file is gitignored;
`scep_ca.pem.example` shows the expected structure.

## Building & testing

### Build environments

`make build` / `flash` / `ota` select the board with a positional **model
arg** -- `s3` (default), `s3zero`, `s3debug`, or `s3zerodebug`. That's the
everyday syntax used throughout this README. Each model maps to a
PlatformIO env:

| Model arg | PlatformIO env | Purpose | Build flag |
|---|---|---|---|
| `s3` (default) | `esp32s3` | ESP32-S3-DevKitC-1 N16R8 hardware | -- |
| `s3zero` | `esp32s3_zero` | Waveshare ESP32-S3-Zero hardware | `-DESPTTY_BOARD_ZERO` |
| `s3debug` | `esp32s3_debug` | DevKitC-1, debug-console build (see [Debug-console builds](#debug-console-builds)) | omits TinyUSB; `ESP_LOG*` → USB-Serial-JTAG |
| `s3zerodebug` | `esp32s3_zero_debug` | Zero, debug-console build | omits TinyUSB; `ESP_LOG*` → USB-Serial-JTAG |
| -- (env only) | `wokwi` | Wokwi simulator + QEMU smoke tests | `-DBRIDGE_LOOPBACK=1` (rings wired back-to-back, TinyUSB bypassed) |
| -- (env only) | `native` | host unit tests | `-DRING_NATIVE=1 -DUNIT_TEST` (plus stubs from `test/stubs/`) |

```
make build                          # DevKitC (default)
make build s3zero                   # Zero build
make flash                          # DevKitC + USB upload
make flash s3zero                   # Zero + USB upload (hold BOOT+RESET first)
make ota <target>                   # DevKitC + OTA upload
make ota <target> s3zero            # Zero + OTA upload
make test                           # native unit tests + pytest scripts
pio run -e wokwi                    # Wokwi build (no flash)
```

The `wokwi` and `native` envs have no model arg -- they aren't flash
targets, so reach them directly with `pio run -e wokwi` / `pio test -e
native` (or `make test`). If you ever need to name a PlatformIO env
explicitly, `ENV=<env>` (e.g. `ENV=esp32s3_zero`) is a lower-level
override that takes precedence over the positional model arg.

`make clean [model]` wipes `.pio/build/<env>/` and the merged
`sdkconfig.<env>` so the next build re-runs cmake configure. Run it after
editing `sdkconfig.defaults` -- ESP-IDF ignores changes to the defaults
once a merged `sdkconfig.<env>` exists. With no model it cleans every
board env.

### Tests

All tests run on a Linux/macOS host without ESP32 hardware:

| Tier | Command |
|---|---|
| Native Unity unit tests | `pio test -e native` |
| pytest integration scripts (OTA protocol, OTA send unit, SCEP protocol, patch applier) | `make test-py` |
| QEMU / shell scripts (QEMU boot, NVS persistence, clean build, patch application) | per script in `test/scripts/` |
| Wokwi simulator | open `test/wokwi/wokwi.toml` |

`make test` runs the first two tiers together. The native suite covers
every library in `lib/` end-to-end plus the helpers extracted from
`main/`. See [`test/README.md`](test/README.md) for the per-suite breakdown.

## Flashing & recovery

The project supports four ways to put a firmware image on a device:

| Procedure | When to use |
|---|---|
| `make flash [devname] [model]` | Local USB; esptool drives the CH340/JTAG reset |
| `make flash-online [devname] [model]` | Local USB; software-only DFU reflash of a running non-debug build (no BOOT+EN press) |
| `make ota <devname\|host> [model]` | Device is running and reachable over Wi-Fi (see [OTA updates](#ota-updates)) |
| `scripts/reboot_to_bootloader.py` | Recovery: drop a wedged-but-running device into ROM USB DFU so `dfu-util` or `esptool` can take over |

### Decision matrix

| I have...                                                | ...and I want to flash via...                | Use |
|---|---|---|
| Local USB cable, device boots production firmware         | USB                                           | `make flash <dev>` -- esptool drives DTR/RTS via the CH340 (DevKitC) or the BOOT+EN buttons (Zero) |
| Local USB cable, device boots a `*_debug` build           | USB                                           | `make flash <dev> s3debug` / `s3zerodebug` -- esptool over the native USB-Serial-JTAG (303a:1001) |
| Local USB cable, device firmware is wedged (no Wi-Fi, BOOT inaccessible) | USB recovery                                  | `scripts/reboot_to_bootloader.py /dev/ttyACM0` then `make flash` |
| Local USB cable, device is running non-debug build, want a software-only reflash | USB DFU                                  | `make flash-online <dev>` (CDC magic -> 303a:0009 -> dfu-util, no buttons) |
| Device on the production Wi-Fi, OTA key in agent          | Wi-Fi                                         | `make ota <dev>` |
| Need to flash a *new* device for the first time           | USB                                           | `make flash <dev>` -- OTA cannot bootstrap an unprovisioned device |

### make flash (local USB)

The default path. `pio run` builds, then esptool resets the chip into the
ROM serial bootloader and writes flash:

```
make flash                          # DevKitC (default), auto-detects the CH340 port
make flash <devname>                # symlink config.h -> config.<dev>.h, then flash
make flash s3zero                   # Zero build
```

On the **DevKitC** esptool drives DTR/RTS through the CH340 auto-reset
circuit; nothing to press. On the **Zero** there is no CH340 and no
auto-reset circuit -- enter download mode manually: hold the BOOT button,
tap RESET, release BOOT. The ROM bootloader enumerates as `303a:1001`
(USB JTAG/serial); `scripts/detect_upload_port.sh` detects it
automatically when no CH340 is present. Then:

```
make flash s3zero
```

### Debug-console builds

For bring-up without an external USB-UART dongle, use a debug-console
build. It skips TinyUSB so the ESP32-S3's built-in USB-Serial-JTAG
controller claims the shared GPIO19/20 pins and the boot log streams
directly from the USB-C port as a `303a:1001` CDC ACM device. Wi-Fi, SSH
(TCP 22), OTA, SCEP, and mDNS all remain functional.

```
make flash <devname> s3zerodebug    # Zero: debug-console build
make flash <devname> s3debug        # DevKitC-1: debug-console build
```

Read the boot log:

```
pio device monitor                  # or: picocom /dev/ttyACM0  (303a:1001)
```

When you're done debugging, switch back to the production build, which
re-enables the TinyUSB CDC SSH bridge:

```
make flash <devname> s3zero         # back to production (TinyUSB bridge)
```

The Zero still requires the BOOT+RESET dance to enter download mode even
in debug-console builds -- the USB-Serial-JTAG controller does not support
auto-reset.

Debug builds also help on the Zero, which lacks the CH340: ESP-IDF
`ESP_LOG*` output otherwise goes to UART0 on GPIO43 (TX) / GPIO44 (RX),
needing an external USB-UART dongle at 115200 baud. Set
`UDP_LOG_HOST`/`UDP_LOG_PORT` in `config.h` to mirror `ESP_LOG` to UDP.

### make flash-online

Software-only reflash of a running non-debug build over a local USB
cable -- no BOOT+EN press, no esptool RTS reset (which fails against
the active TinyUSB CDC with EPROTO):

```
make flash-online              # uses current main/config.h
make flash-online <devname>    # symlink main/config.h -> config.<dev>.h, then flash
make flash-online <devname> s3zero
make flash-online TRIG_PORT=/dev/ttyACM1   # override CDC-port autodetect
```

Pipeline: build + `mkdfu.py` -> `scripts/reboot_to_bootloader.py` writes
the CDC boot-trigger magic to the running TinyUSB endpoint -> the
firmware's matcher in `lib/usb_cdc_boot_trigger/` reboots into ROM USB
DFU (`303a:0009`) -> `dfu-util -d 0x303a:0x0009 -a 0 -R -D firmware.dfu`
writes flash and resets.

Non-debug builds only. Debug builds skip TinyUSB, so there is no CDC
matcher to feed -- and they don't need it: `make flash` already works
over their USB-Serial-JTAG endpoint.

Host needs `dfu-util` and `usbutils` (for `lsusb`); on Debian:
`apt install dfu-util usbutils`.

### Pipeline diagrams

```
make flash       :  pio run -> esptool -> CH340 UART (DevKitC) ........... -> ROM serial bootloader
                                       \-> USB-Serial-JTAG 303a:1001 (Zero/debug, BOOT+EN dance)

make flash-online:  pio run -> mkdfu -> CDC magic -> 303a:0009 -> dfu-util -R   (local; non-debug envs only)

make ota         :  pio run -> ota_send.py -> SSH (ota@dev) -> X25519+AES-GCM -> inactive OTA slot
                                                            -> otadata flip + reboot + self-test + rollback-on-fail
```

### USB VID:PID by chip state

| VID:PID | State / what produces it | Used by |
|---|---|---|
| `1a86:55d3` | CH340 USB-UART on DevKitC-1 (always present on that board) | `make flash` (default) |
| `303a:0009` | ESP32-S3 ROM USB DFU endpoint (entered after boot-trigger magic, or BOOT+EN held through power-up) | `make flash-online` (`dfu-util`) |
| `303a:1001` | ESP32-S3 USB-Serial-JTAG controller (ROM bootloader after BOOT+EN dance, or any `*_debug` running firmware) | `make flash` on Zero / debug envs |
| `303a:xxxx` / `303a:4001` | TinyUSB CDC ACM running app -- `USB_PID` value from `config.h` (`xxxx` in the deployed configs, `4001` in `config.example.h`) | The SSH<->serial bridge data path; also where `reboot_to_bootloader.py` writes the magic |

### Recovery procedures

- **Firmware is up but Wi-Fi/OTA is broken**, BOOT button inaccessible:
  run `make flash-online <dev>` (CDC magic + dfu-util in one shot), or
  the lower-level `scripts/reboot_to_bootloader.py /dev/ttyACM<TinyUSB>`
  followed by `make flash`. Both rely on the CDC boot-trigger magic,
  which only works for non-debug builds. For a debug build, the device
  is already at `303a:1001` -- jump straight to `make flash`.

- **Device is in ROM DFU (`303a:0009`) and `dfu-util` will not detach**
  (e.g. stale udev state): physically tap the EN/RESET button on the
  devkit, or for the Zero hold BOOT and tap RESET to re-enter the ROM
  bootloader on the USB-Serial-JTAG endpoint, then `make flash`.

- **New firmware crashes on boot**: the OTA rollback path takes over
  automatically after `OTA_ROLLBACK_DELAY_MS`. If both slots are
  bad, the only recovery is USB flash via `make flash` or
  `make flash-online`.

See [`scripts/README.md`](scripts/README.md) for the underlying
helpers, and [`Makefile`](Makefile) for the canonical list of targets.

## OTA updates

```
make ota 192.168.1.42       # raw IP or hostname
make ota esp-tty.local
make ota alpha              # per-device config (see Configuration)
```

`make ota` builds the current `main/config.h` (or the `config.<devname>.h`
you named) and runs `scripts/ota_send.py <host> .pio/build/<env>/firmware.bin`
(`<env>` is the selected model's build env -- `esp32s3` for the default DevKitC build).
SSH auth uses your `~/.ssh/agent` / `~/.ssh/config`; the matching key must
be the one whose public half is `OTA_AUTHORIZED_PUBKEY`.

Inside the SSH session, both sides generate ephemeral X25519 keypairs,
exchange public halves, derive a shared secret, and HKDF-SHA256 it (with
salt `esp-tty-ota-v2` and info = `client_pub || device_pub`) into a
32-byte AES-256-GCM key. The client encrypts the firmware once,
sends `[len|iv|tag|ciphertext]`, the device decrypts into PSRAM,
verifies the auth tag, writes the plaintext to the inactive OTA slot,
flips otadata, and reboots. The new firmware self-marks valid after
`OTA_ROLLBACK_DELAY_MS`; if it crashes or wedges before then, the
bootloader rolls back automatically.

A failed auth-tag check aborts the upload; the active boot partition is
never modified. The only OTA credential is the SSH key matching
`OTA_AUTHORIZED_PUBKEY` -- the encryption key is derived per-upload and
never persisted.

Wire protocol details are in the header of `scripts/ota_send.py` and
`main/ota_session.c`.

## Architecture

```mermaid
flowchart LR
    target["Linux server<br/>(USB-serial)"]
    client["SSH client<br/>(ssh tty@...)"]

    subgraph esp["ESP32-S3 firmware"]
        direction TB
        rx["cdc_rx_callback<br/>(TinyUSB)"]
        sb[("scrollback<br/>128 KB PSRAM")]
        u2s[("usb_to_ssh ring<br/>16 KB PSRAM")]
        ssh{{"wolfSSH session<br/>TCP 22"}}
        s2u[("ssh_to_usb ring<br/>16 KB PSRAM")]
        tx["usb_tx_task<br/>(TinyUSB)"]

        rx --> sb
        rx --> u2s
        u2s -- "pump_usb_to_ssh" --> ssh
        ssh -- "pump_ssh_to_usb" --> s2u
        s2u --> tx
    end

    target -- "USB-C" --> rx
    tx -- "USB-C" --> target
    ssh -- "Wi-Fi" --> client
    client -- "Wi-Fi" --> ssh
```

A single FreeRTOS `ssh_server_task` runs the accept loop. On each
connection it authenticates the user and, for `tty@`, spawns two pump
tasks that move bytes between the wolfSSH stream and the rings. The
TinyUSB callback (RX) and `usb_tx_task` (TX) are persistent and reuse
the same rings across sessions.

## Security model

Authentication is public-key only. Authorized keys are baked into the
firmware from `config.h` at build time; rotating them is a firmware
re-flash.

The threat model is a network attacker. A physical attacker who can dump
the SPI flash extracts the NVS key from the `nvs_keys` partition and
decrypts the on-device NVS (which holds the ED25519 host key and, in
Mode C, the SCEP-issued device cert + private key). The authorized
public keys live in firmware flash, unencrypted but useless on their
own. OTA uploads require the ED25519 private key matching
`OTA_AUTHORIZED_PUBKEY`, held off-device by the operator; the ephemeral
X25519 exchange inside the OTA session adds an independent encryption
layer with no key material baked into firmware.

Cipher hardening:
- AES-CBC, AES-192, SHA-1 MAC, and DH key exchange are disabled in
  `components/wolfssl/include/user_settings.h`.
- The runtime cipher list is pinned to `aes256-gcm@openssh.com` only via
  `wolfSSH_CTX_SetAlgoListCipher`.

No eFuses are burned. SPI flash encryption (which would close the
physical-extraction gap) is permanent and would block reflashing; it's
intentionally out of scope.

## Repository layout

| Path | What's there |
|---|---|
| [`main/`](main/README.md) | Firmware entry point and ESP-IDF-dependent code (`main.c`, `wifi.c`, `ssh_server.c`, `ota_session.c`, `scep_enroll.c`, `cert_renewer.c`, `usb_cdc.c`, `host_key.c`) |
| [`main/certs/`](main/certs/README.md) | EAP-TLS client certificates (Mode B) and the SCEP CA trust anchor (Mode C); gitignored except `.example` stubs |
| [`lib/`](lib/README.md) | Platform-agnostic libraries: `ring`, `bridge`, `scrollback`, `pubkey_auth`, `cred_store`, `scep_proto`, `scep_transport`, `wifi_state`, `wifi_backoff`, `cert_renewer`, `rollback_decision`, `ssh_keepalive`, `term_resize`, `usb_cdc_drain`, `usb_cdc_boot_trigger`, `mdns_dispatch`, `udp_log`, `util` |
| [`components/`](components/README.md) | Local ESP-IDF components (wolfSSL bridge) |
| [`boards/`](boards/README.md) | Project-local PlatformIO board manifests |
| [`patches/`](patches/README.md) | Patches applied to `managed_components/` at cmake configure |
| [`scripts/`](scripts/README.md) | Build hooks, OTA client, key generation, port detection |
| [`test/`](test/README.md) | Native unit tests, QEMU/Wokwi configs, pytest scripts, stubs |
| `partitions.csv` | 16 MB A/B OTA partition table (DevKitC-1) |
| `partitions_zero.csv` | 4 MB A/B OTA partition table (ESP32-S3-Zero) |
| `platformio.ini` | Build environment definitions |
| `sdkconfig.defaults` | Base ESP-IDF sdkconfig overrides |
| `sdkconfig.zero.defaults` | Delta sdkconfig overrides for the Zero (4 MB flash, QSPI PSRAM) |
| `Makefile` | `make build` / `make flash` / `make ota` wrappers around PlatformIO |
| `requirements.txt` | Python dependencies (PlatformIO, paramiko, cryptography) |

Each subfolder has its own README with details on the files it contains.

## Scope

- One SSH session at a time. The target's serial console is a single
  shared resource; a new connection preempts the active one. No
  multiplexing layer.
- mDNS / Bonjour is opt-in via `MDNS_ENABLE`. Off by default.
- Serial-data bridge only. GPIO control of the target's reset or boot
  pins is out of scope.
- eFuses are left unprogrammed so the device stays reflashable. See
  "Security model" for the implications.

## License

[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

If you run a modified version of this firmware on a device that
interacts with users over a network -- e.g. an SSH server reachable
beyond your own machines -- the AGPL requires you to make the
corresponding source available to those users. The full license text
is in [`LICENSE`](LICENSE).

Bundled components ship under their own licenses: wolfSSL/wolfSSH
(GPL-2.0-or-later or commercial), mbedTLS (Apache-2.0), TinyUSB (MIT),
ESP-IDF (Apache-2.0).
