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

After the device reboots it will re-enumerate as VID:PID 303a:1001
(native USB-Serial-JTAG, ROM bootloader) and esptool / make flash can
then write firmware over USB.

Exits 0 on send success.  Does NOT wait for / verify the bootloader
re-enumeration -- the kernel hot-plug handler is the reliable signal
for that.
"""

import argparse
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
    ap.add_argument("--baud", type=int, default=115200,
                    help="Baud rate (ignored on CDC ACM, but the kernel "
                         "termios interface still wants a value)")
    args = ap.parse_args()

    try:
        import serial
    except ImportError:
        print("error: pyserial not installed.  pip install pyserial",
              file=sys.stderr)
        return 2

    print(f"[reboot] opening {args.port} ...")
    # rtscts/dsrdtr off so we don't trigger any auto-reset wiring on the
    # devkit ports (Zero doesn't have one but other esp-tty boxes do).
    try:
        ser = serial.Serial(args.port, args.baud, timeout=1,
                            rtscts=False, dsrdtr=False)
    except serial.SerialException as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    # Deassert DTR/RTS for the same reason.
    ser.setDTR(False)
    ser.setRTS(False)

    print(f"[reboot] writing {len(MAGIC)} magic bytes ...")
    ser.write(MAGIC)
    ser.flush()
    time.sleep(0.05)  # give the device a beat to process before close
    ser.close()
    print("[reboot] sent.  Device should re-enumerate as 303a:1001 "
          "(ROM bootloader) within ~1s.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
