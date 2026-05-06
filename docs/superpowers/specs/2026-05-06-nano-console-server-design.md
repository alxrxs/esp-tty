# Nano Console Server — Design

**Status:** approved
**Date:** 2026-05-06
**Hardware:** ESP32-S3-DevKitC-1 N16R8 (16MB flash, 8MB PSRAM)

## Goal

A pocket-sized device that turns any USB-attached Linux server into one
reachable over SSH-over-Wi-Fi. From the user's laptop:

```
ssh -p 2222 console@<esp32-ip>
```

…lands directly in the Linux server's `getty` login prompt as if you were
plugged into a serial console — because you are. The ESP32 is the cable.

## Architecture

```
ssh client ──TCP:2222──► ESP32-S3 (wolfSSH server, ED25519 host key)
                            │  decrypted bytes
                            ▼
                      USB CDC (TinyUSB, native OTG)
                            │
                            ▼ USB-C cable
                  Linux host: /dev/ttyACM0 ──► serial-getty ──► bash
```

Single firmware image, three FreeRTOS tasks, two ring buffers:

- **`wifi_task`** — connects to configured SSID (WPA2/WPA3-Personal for v1),
  reconnects on drop, prints IP to UART log.
- **`ssh_task`** — wolfSSH listener on TCP/2222. Single concurrent session.
  Pubkey auth only (no passwords). On accept, allocates a `shell` channel
  with a hardcoded 200×50 PTY and runs the bridge pump.
- **`usb_cdc_task`** — TinyUSB CDC ACM device. Linux sees `/dev/ttyACM0`.
  Reads from CDC RX into `usb_to_ssh` ring buffer; pulls from `ssh_to_usb`
  ring buffer and writes to CDC TX.

The bridge is two `bridge_pump()` loops inside `ssh_task`, one per
direction, both blocking with backpressure. **No drops on either side** —
producers block until the consumer drains.

## Components

```
esp-tty/
├── platformio.ini
├── sdkconfig.defaults                # TinyUSB, wolfSSH, NVS encryption, PSRAM
├── partitions.csv                    # app + nvs + nvs_keys (encrypted NVS)
├── .gitignore                        # ignores main/config.h
├── main/
│   ├── CMakeLists.txt
│   ├── main.c                        # app_main, NVS init, task spawn
│   ├── config.h.example              # template for SSID, pubkey, port
│   ├── config.h                      # gitignored, user fills in
│   ├── wifi.c / wifi.h               # connect + reconnect loop
│   ├── usb_cdc.c / usb_cdc.h         # TinyUSB init, CDC RX/TX tasks
│   ├── ring.c / ring.h               # thin StreamBuffer wrapper (testable)
│   ├── bridge.c / bridge.h           # pure pump logic (host-testable)
│   ├── ssh_server.c / ssh_server.h   # wolfSSH session lifecycle
│   └── host_key.c / host_key.h       # generate-or-load ED25519 from NVS
├── components/
│   └── (wolfssh added via idf_component.yml)
├── test/
│   ├── native/                       # PlatformIO native env tests
│   │   ├── test_bridge.c             # pump correctness, lossless, backpressure
│   │   └── test_ring.c               # ring buffer semantics
│   └── wokwi/
│       ├── diagram.json              # Wokwi ESP32-S3 board + Wi-Fi
│       └── wokwi.toml
└── docs/superpowers/specs/2026-05-06-nano-console-server-design.md
```

## Key design decisions

### Configuration

Compile-time via `main/config.h`. Template `config.h.example` is checked in;
real `config.h` is gitignored. Contains:

- `WIFI_SSID`, `WIFI_PASS`
- `SSH_PORT` (default 2222)
- `AUTHORIZED_PUBKEY` — single OpenSSH-format ED25519 public key string

Runtime provisioning (captive portal, etc.) is explicitly out of scope for
v1. If you want to change creds, edit `config.h` and reflash.

### Host key

Generated on first boot using wolfCrypt ED25519 + ESP-IDF hardware RNG.
Stored in encrypted NVS partition under key `ssh/host_ed25519`. On boot,
`host_key_load_or_generate()` returns the key. Fingerprint (SHA-256) is
printed to UART log so the user can verify on first SSH connection.

Reset path: `idf.py erase-flash` wipes NVS → next boot generates a fresh
host key. **No eFuses are burned anywhere in v1.** Everything is reversible.

### Lossless CDC

Both ring buffers are 16 KB FreeRTOS `StreamBuffer`s allocated in PSRAM.
Producers use blocking sends with no timeout. Consumers use blocking
receives. Under sustained backpressure, the producing side stalls — for an
interactive console this manifests as the remote side briefly waiting,
which is correct behavior.

The ring abstraction (`ring.h`) wraps `StreamBuffer` so the same interface
has a host implementation backed by `pthread_mutex` + `pthread_cond` for
native tests.

### Bridge pump (testable core)

`bridge.c` exports:

```c
typedef int (*read_fn)(void *ctx, uint8_t *buf, size_t cap);
typedef int (*write_fn)(void *ctx, const uint8_t *buf, size_t len);

void bridge_pump(read_fn r, void *r_ctx,
                 write_fn w, void *w_ctx,
                 volatile bool *stop);
```

No ESP-IDF, no FreeRTOS, no wolfSSH dependencies. Pure C. The native test
wires two `bridge_pump` instances back-to-back through in-memory pipes and
asserts:

- All bytes written on side A appear on side B in order
- No bytes are dropped under producer-faster-than-consumer load
- `stop` flag terminates within one pump iteration

### Single session

When a second client connects while one is active, the new connection is
accepted, the old session's wolfSSH context is shut down cleanly, and the
new one takes over. Two concurrent shells on one TTY is chaos — explicit
takeover is preferable.

### PTY size

Hardcoded 200×50 for v1. SSH `pty-req` is accepted but dimensions are
ignored. SSH `window-change` requests are dropped. Negotiation is a v2
feature.

## Out of scope for v1

- WPA2/WPA3-Enterprise + EAP-TLS (UPB / eduroam). `wifi.c` will have a
  clearly-marked extension point. Switching later means populating an
  `wifi_sta_config_t` enterprise struct, not restructuring code.
- DS peripheral / eFuse-backed key storage. `host_key.c` exposes a single
  `host_key_load_or_generate()` function; swapping NVS for DS is a
  one-file change.
- Secure Boot v2, flash encryption (eFuse-bound).
- WireGuard.
- Multiple concurrent SSH sessions.
- Runtime provisioning UI.
- mDNS. Connect by IP from UART log.

## Testing strategy

Three layers, in order of coverage vs. cost:

### 1. Native unit tests (`pio test -e native`)

Runs on macOS and Linux today, no hardware. Targets:

- `test_ring.c` — ring buffer FIFO correctness, blocking semantics, wrap
- `test_bridge.c` — `bridge_pump` losslessness under pressure, ordering,
  clean shutdown via `stop` flag

CI matrix runs this env on both `macos-latest` and `ubuntu-latest` runners.

### 2. Wokwi integration test (`pio test -e wokwi` or manual)

Real firmware in Wokwi's ESP32-S3 simulator. Wokwi provides Wi-Fi but no
USB peripheral emulation, so for this test the CDC layer is replaced by a
**loopback shim** (compile flag `BRIDGE_LOOPBACK=1`) that connects
`ssh_to_usb` directly to `usb_to_ssh`. Test script:

1. Boot firmware in Wokwi
2. SSH in from the test runner with a known keypair
3. Send "hello\n", expect "hello\n" echoed back
4. Validate fingerprint matches the one the firmware logs

This validates: wolfSSH wire compat with OpenSSH, Wi-Fi join, host key
load/save, pubkey auth, the bridge pump end-to-end. It does **not**
validate TinyUSB.

### 3. Hardware bring-up checklist

Documented in `README.md`. Steps when board arrives:

1. `pio run -e esp32s3 -t upload` (hold BOOT, plug UART port)
2. Open UART monitor, watch for IP and host key fingerprint
3. Move USB-C cable to native USB port; on Linux server check
   `dmesg | grep ttyACM` and `lsusb | grep NanoConsole`
4. `sudo systemctl enable --now serial-getty@ttyACM0.service`
5. From laptop: `ssh -p 2222 console@<ip>`, verify fingerprint, log in
6. Smoke test: `yes | head -10000` — verify no drops, no corruption

## CI

GitHub Actions workflow `.github/workflows/ci.yml`:

- `build` job: `pio run -e esp32s3` — verifies firmware compiles
- `test-native` job (matrix: macos, ubuntu): `pio test -e native`
- `test-wokwi` job: optional, runs the Wokwi CLI if `WOKWI_CLI_TOKEN`
  secret is present

## Open questions resolved during brainstorming

| Question | Decision |
|---|---|
| Build system | PlatformIO + ESP-IDF |
| Auth model | Embedded ED25519 pubkey, host key in NVS |
| eFuses | None burned in v1 — fully resettable |
| SSH port | 2222 |
| mDNS | No, IP from UART log |
| CDC loss policy | Lossless, blocking with backpressure |
| PTY size | Hardcoded 200×50, no negotiation in v1 |
| Test envs | Native (macOS + Linux) + Wokwi |
