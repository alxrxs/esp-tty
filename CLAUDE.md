# Notes for AI assistants working on this firmware

## ESP32-S3-DevKitC-1 N16R8 hardware quirks

The devkit exposes two USB endpoints when plugged in, but **which `/dev/ttyACM*`
device is which depends on what mode the chip is in**.

### Port layout

| `/dev/ttyACM?` | USB VID:PID | What it is | When it appears |
|---|---|---|---|
| usually `ttyACM0` | `1a86:55d3` | CH340 USB-UART, wired to ESP32-S3 UART0 (the boot-ROM and `ESP_LOG*` console) | Always, regardless of chip state |
| usually `ttyACM1` | `303a:1001` (download mode) | ESP32-S3 native USB Serial-JTAG | Only while the bootloader is running or no app has taken over native USB |
| usually `ttyACM1` | `303a:4001` (running app) | esp-tty's own TinyUSB CDC endpoint (the SSH-bridge data path) | Once `main.c` has called `tinyusb_driver_install` |

The CH340 (`ttyACM0`) is the **only port that carries the ESP-IDF boot log
across all chip states**. The JTAG port (`ttyACM1` at `303a:1001`)
disappears the moment TinyUSB takes over native USB and gets replaced by
the firmware's CDC endpoint (`303a:4001`).

### Reset procedures

**The CH340's RTS/DTR auto-reset wiring on this devkit is unreliable.**
esptool's default `--before default_reset --after hard_reset` against
`ttyACM0` will frequently leave the chip in an indeterminate state or
fail to reboot it. Don't waste time on it.

Use one of the following instead:

1. **Physical EN button on the devkit.** Always works.
2. **`make flash`.** PlatformIO drives the reset through the correct
   USB path; this is the canonical way to reset and reflash in one step.
3. **`esptool --port /dev/ttyACM1 --chip esp32s3 --before usb_reset --after no_reset run`**
   when `ttyACM1` is the JTAG interface (`303a:1001`). `usb_reset` issues
   a USB control transfer that the JTAG peripheral honours regardless of
   RTS/DTR wiring. Will NOT work once the running app has remapped
   `ttyACM1` to its TinyUSB CDC endpoint (`303a:4001`) -- at that point
   you'd be poking the bridge, not the bootloader.

### Capturing the boot log

Opening `/dev/ttyACM0` naively from Python or `cat` can trigger a spurious
reset and/or fail because the CH340 expects RTS and DTR to be deasserted
first. The pattern that works:

```python
import serial
uart = serial.Serial('/dev/ttyACM0', baudrate=115200, timeout=0.1,
                     xonxoff=False, rtscts=False, dsrdtr=False)
uart.setRTS(False)
uart.setDTR(False)
uart.reset_input_buffer()
# then read in a loop
```

Or simply `pio device monitor` / `make monitor` -- PlatformIO does the
right termios setup. For a one-shot capture, `picocom -b 115200 --noinit
--noreset /dev/ttyACM0` also works.

### Flash partition addresses

The project uses OTA with two app slots; the partition table is in
`partitions.csv`. The relevant offsets for a manual `esptool write_flash`
(rarely needed -- prefer `make flash`):

| Offset | Contents |
|---|---|
| `0x0` | bootloader |
| `0x8000` | partition table |
| `0x10000` | `ota_data_initial.bin` -- selects which slot boots. **Not the app.** |
| `0x20000` | `firmware.bin` -- the app, in slot `ota_0` |
| `0x420000` | slot `ota_1` -- empty until first OTA upload |

Flashing the app to `0x10000` (the address you'd use on a non-OTA layout)
will corrupt the otadata partition and the bootloader will refuse to
hand off to either slot.
