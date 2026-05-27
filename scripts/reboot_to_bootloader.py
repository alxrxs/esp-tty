#!/usr/bin/env python3
"""
reboot_to_bootloader.py -- send the USB-CDC magic that forces a running
esp-tty firmware to reboot into the ROM serial bootloader.

This is the recovery path for ESP32-S3-Zero devices when:

  - WiFi is down or misconfigured (so OTA is impossible), AND
  - The BOOT button is physically inaccessible (deployed device).

The magic is recognised only on the USB CDC RX endpoint -- never over
SSH -- so this requires a USB cable plugged into the device.  See
lib/usb_cdc_boot_trigger/usb_cdc_boot_trigger.{h,c} for the matcher.

Usage:
    scripts/reboot_to_bootloader.py /dev/ttyACM0

After the device reboots it will re-enumerate as VID:PID 303a:0009
(ESP32-S3 ROM USB DFU endpoint).  esptool / `pio run --target upload`
can then write firmware over USB without any physical button presses.

Implementation note: this script deliberately does NOT use pyserial.
pyserial.Serial.open() unconditionally issues TIOCMBIC on the RTS line
via fcntl.ioctl(); TinyUSB's CDC ACM stack in the running firmware
rejects that control transfer with EPROTO ("Protocol error"), and the
open() call fails before any bytes can be written.  os.open() opens the
fd without touching termios, so the magic write reaches the device.

Exits 0 on send success.  Does NOT wait for / verify the bootloader
re-enumeration -- the kernel hot-plug handler is the reliable signal
for that.
"""

import argparse
import os
import sys
import time

# Must stay byte-for-byte identical to k_magic[] in
# lib/usb_cdc_boot_trigger/usb_cdc_boot_trigger.c
MAGIC = b"\nESPTTY_REBOOT_TO_BOOTLOADER_xK9w7Pq3J8dHvR_NOW\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("port",
                    help="Serial device of the running esp-tty firmware "
                         "(typically /dev/ttyACM0)")
    args = ap.parse_args()

    if not os.path.exists(args.port):
        print(f"error: {args.port}: no such device", file=sys.stderr)
        return 1

    # Bypass pyserial.  See the docstring for why.
    try:
        fd = os.open(args.port, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as exc:
        print(f"error: open {args.port}: {exc}", file=sys.stderr)
        return 1

    try:
        n = os.write(fd, MAGIC)
        if n != len(MAGIC):
            print(f"warn: short write ({n} of {len(MAGIC)} bytes)",
                  file=sys.stderr)
        else:
            print(f"[reboot] wrote {n} magic bytes to {args.port}")
        # Give the kernel driver a beat to push the URB to the device
        # before we close the fd.
        time.sleep(0.1)
    except OSError as exc:
        print(f"error: write: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            os.close(fd)
        except OSError:
            pass

    print("[reboot] sent.  Device should re-enumerate as 303a:0009 (DFU) "
          "(ROM bootloader) within ~1s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
