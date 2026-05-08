# test/wokwi/ — Wokwi Simulator Configuration

```
test/wokwi/
  diagram.json    Circuit diagram (single ESP32-S3-DevKitC-1 board, no external parts)
  wokwi.toml      Simulator manifest pointing to the wokwi build outputs
```

## What wokwi is

Wokwi is a browser-based ESP32 simulator. It can run the same firmware binary
as the real hardware for logic and protocol testing, without requiring physical
components.

The files in this directory configure Wokwi to run the `wokwi` PlatformIO
environment. That environment compiles the firmware with `BRIDGE_LOOPBACK=1`,
which bypasses TinyUSB CDC and wires the two ring buffers directly together so
the SSH bridge works without a USB host. Wi-Fi is also simulated; the device
connects to Wokwi's virtual network.

## wokwi.toml

```toml
[wokwi]
version  = 1
elf      = "../../.pio/build/wokwi/firmware.elf"
firmware = "../../.pio/build/wokwi/firmware.bin"
```

Points the simulator at the ELF and binary built by `pio run -e wokwi`. The
paths are relative to this file and resolve to the PlatformIO build output
directory.

## diagram.json

Defines a single board component: `board-esp32-s3-devkitc-1` with 16 MB flash
and 8 MB PSRAM, matching the N16R8 module used in production. No external
connections or components are wired up; the firmware needs only the on-chip
peripherals (Wi-Fi, PSRAM) that the simulator provides.

## Building the wokwi firmware

```
pio run -e wokwi
```

The output appears in `.pio/build/wokwi/`. The Wokwi browser extension or
Wokwi CLI will pick up `firmware.elf` and `firmware.bin` from there when pointed
at this directory.

## Relationship to the QEMU smoke test

The QEMU smoke test (`test/scripts/test_qemu_boot.py`) also uses the `wokwi`
PlatformIO environment to build the firmware (the `BRIDGE_LOOPBACK=1` flag is
what makes it compatible with both simulators). QEMU and Wokwi consume the same
binary; their simulator fidelity and available peripheral emulation differ.

Wokwi provides a visual interface and supports interactive testing. QEMU
(`qemu-system-xtensa`, Espressif fork) provides a command-line interface
suitable for automated script-based testing, which is what the test scripts use.

Note: `qemu-system-xtensa` for ESP32-S3 does not emulate a network interface
that the firmware can drive over TCP, so a live SSH connection into QEMU is not
feasible. A real SSH session requires physical ESP32-S3 hardware.
