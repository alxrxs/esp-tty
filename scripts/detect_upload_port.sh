#!/bin/sh
# detect_upload_port.sh -- print the device node of the CH340/CH343 USB-UART
# bridge typically used to flash ESP32-S3 dev boards.  Prints nothing if no
# such device is connected; the Makefile then falls back to PlatformIO's
# own auto-detect.
#
# Why this exists: this firmware exposes the ESP32-S3's native USB as a
# CDC ACM device (the SSH<->USB bridge endpoint).  On modern Linux/macOS that
# CDC interface enumerates with the SAME name pattern as a USB-UART bridge
# (e.g. /dev/cu.usbmodem* on macOS Big Sur+), so we can't tell them apart
# by filename.  We have to ask the kernel for the USB Vendor ID instead:
# CH340/CH343 = WCH = VID 0x1A86 (6790 decimal).

case "$(uname -s)" in
    Darwin)
        # macOS: walk the IOUSBHostDevice tree looking for VID 6790, then
        # capture the first IOCalloutDevice (i.e. /dev/cu.*) below it.
        ioreg -r -c IOUSBHostDevice -l 2>/dev/null | awk '
            /IOUSBHostDevice/ { in_dev = 1; is_ch340 = 0 }
            in_dev && /"idVendor" = 6790/ { is_ch340 = 1 }
            is_ch340 && /"IOCalloutDevice"/ {
                if (match($0, /\/dev\/cu\.[^"]+/)) {
                    print substr($0, RSTART, RLENGTH)
                    exit
                }
            }
        '
        ;;
    Linux)
        # udev creates a stable /dev/serial/by-id/ symlink for each USB-UART
        # bridge.  CH340 = "1a86".  Globbing the symlink gives us the first
        # one even if multiple are connected.
        for path in /dev/serial/by-id/usb-1a86_*; do
            [ -e "$path" ] || continue
            echo "$path"
            exit
        done
        ;;
    *)
        # Other OSes (Windows under WSL, BSDs, ...): let PlatformIO auto-detect.
        ;;
esac
