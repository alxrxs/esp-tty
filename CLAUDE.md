# Notes for AI assistants working on this firmware

## ESP32-S3-DevKitC-1 N16R8 hardware quirks

The devkit exposes two USB endpoints when plugged in. Which `/dev/ttyACM*`
device is which depends on what the chip is currently doing.

### Port layout

| device | USB VID:PID | what it is | when present |
|---|---|---|---|
| `ttyACM0` | `1a86:55d3` | CH340 USB-UART wired to ESP32-S3 UART0 (the boot-ROM and `ESP_LOG*` console) | always |
| `ttyACM1` | `303a:1001` | ESP32-S3 native USB Serial-JTAG (download/bootloader interface) | only while the bootloader is running, or while no app has claimed native USB |
| `ttyACM1` | `303a:4001` | esp-tty's TinyUSB CDC endpoint (the SSH-bridge data path the Linux host uses) | once `main.c` calls `tinyusb_driver_install` |
| `ttyACM1` | `303a:0009` | ESP32-S3 ROM USB DFU endpoint -- entered after the USB-CDC boot-trigger magic, or after BOOT+EN held through power-up | only after `scripts/reboot_to_bootloader.py`, `make flash-online`, or manual BOOT+EN; `dfu-util` is the only tool that talks to this PID |

`USB_PID` is configurable in `config.h`; the example template uses
`0x4001` and a deployment may pick any value.  Either way the
running TinyUSB endpoint is what `reboot_to_bootloader.py` and
`make flash-online` write the magic to.

ttyACM0 (CH340) is the **only port that carries the ESP-IDF boot log
across all chip states**. ttyACM1 swaps identity between `1001` (JTAG)
and `4001` (running app) on every reset; don't hard-code which one it
is at any given moment -- check the VID:PID.

### Auto-reset works -- it is just the standard ESP devkit circuit

The devkit has the usual two-transistor auto-reset wiring: DTR drives a
transistor that pulls IO0 low, RTS drives another that pulls EN low,
arranged so a port-open or RTS/DTR pulse from the host can put the
chip into download mode or hard-reset it. `esptool --before
default_reset --after hard_reset` against `/dev/ttyACM0` is reliable
and is what `make flash` uses under the hood.

**Side effect:** opening ttyACM0 with default Linux termios asserts
DTR+RTS, which the auto-reset circuit interprets as a reset pulse, so
the chip reboots the instant `cat /dev/ttyACM0` runs. This is *by
design*, not a fault. Tools that want to read the running console
without resetting must explicitly deassert the lines first:

- `picocom --noreset -b 115200 /dev/ttyACM0`
- `pio device monitor` -- safe by default
- pyserial:
  ```python
  import serial
  uart = serial.Serial('/dev/ttyACM0', 115200, timeout=0.1,
                       rtscts=False, dsrdtr=False)
  uart.setRTS(False)
  uart.setDTR(False)
  uart.reset_input_buffer()
  ```

If you want to capture the boot log specifically (i.e. you *want* a
reset), the simplest pattern is to start a non-resetting reader, then
trigger the reset through a separate process: `esptool --port
/dev/ttyACM0 --chip esp32s3 --before default_reset --after hard_reset
run`, or press the EN button on the devkit. Don't try to read from the
same port esptool is driving; the kernel-level open conflict will
truncate the capture.

### Flash partition addresses

The project uses OTA with two app slots; the partition table is in
`partitions.csv`. Relevant offsets for a manual `esptool write_flash`
(rarely needed -- prefer `make flash`):

| offset | contents |
|---|---|
| `0x0` | bootloader |
| `0x8000` | partition table |
| `0x10000` | `ota_data_initial.bin` -- selects which slot boots. **Not the app.** |
| `0x20000` | `firmware.bin` -- the app, in slot `ota_0` |
| `0x420000` | slot `ota_1` -- empty until first OTA upload |

Flashing the app to `0x10000` (the offset for a non-OTA layout) will
corrupt otadata and the bootloader will refuse to hand off to either
slot.
