#!/bin/sh
# detect_upload_port.sh -- print the device node to use for flashing.
#
# Priority 1: CH340/CH343 USB-UART bridge (VID 0x1A86 / 6790 decimal).
#   This is the DevKitC-1 path.  The CH340 is always present and is the
#   correct port to drive esptool against on that board.
#
# Priority 2: ESP32-S3 native USB Serial-JTAG controller
#   (VID 0x303A, PID 0x1001).  Two cases use this PID:
#   a) Zero in ROM bootloader mode: hold BOOT, tap RESET before `make flash`.
#      Once the app starts in production firmware (TinyUSB), the PID changes
#      to 0x4001 (TinyUSB CDC) and this script no longer matches -- intentional.
#   b) USB_DEBUG_CONSOLE_ONLY builds (s3debug / s3zerodebug): the running app
#      does not initialise TinyUSB, so the USB-Serial-JTAG controller keeps
#      the pins and the device continues to enumerate as 303a:1001 even after
#      boot.  In that case the BOOT+RESET dance is still required to enter
#      download mode for flashing (the app has no auto-reset circuit on Zero).
#
# Prints nothing if neither device is found; the Makefile then falls back
# to PlatformIO's own auto-detect.  Override at any time with:
#   make flash PORT=/dev/...
#
# Why this exists: this firmware exposes the ESP32-S3's native USB as a
# CDC ACM device (the SSH<->USB bridge endpoint).  On modern Linux/macOS
# that CDC interface enumerates with the SAME name pattern as a USB-UART
# bridge, so we can't tell them apart by filename.  We have to ask the
# kernel for the USB Vendor ID instead.

case "$(uname -s)" in
    Darwin)
        # macOS: walk the IOUSBHostDevice tree looking for VID 6790 (CH340)
        # first, then 0x303A/PID 0x1001 (ESP32-S3 bootloader).
        # Capture the first IOCalloutDevice (i.e. /dev/cu.*) found.
        port=$(ioreg -r -c IOUSBHostDevice -l 2>/dev/null | awk '
            /IOUSBHostDevice/ { in_dev = 1; is_target = 0; vid = 0; pid = 0 }
            in_dev && /"idVendor" = /  { vid = $NF + 0 }
            in_dev && /"idProduct" = / { pid = $NF + 0 }
            in_dev && vid == 6790 { is_target = 1 }
            is_target && /"IOCalloutDevice"/ {
                if (match($0, /\/dev\/cu\.[^"]+/)) {
                    print substr($0, RSTART, RLENGTH)
                    exit
                }
            }
        ')
        if [ -n "$port" ]; then
            echo "$port"
            exit
        fi
        # Fallback: ESP32-S3 native USB bootloader (Zero, BOOT+RESET held)
        ioreg -r -c IOUSBHostDevice -l 2>/dev/null | awk '
            /IOUSBHostDevice/ { in_dev = 1; vid = 0; pid = 0 }
            in_dev && /"idVendor" = /  { vid = $NF + 0 }
            in_dev && /"idProduct" = / { pid = $NF + 0 }
            in_dev && vid == 12346 && pid == 4097 {
                # VID 0x303A=12346, PID 0x1001=4097
                is_target = 1
            }
            is_target && /"IOCalloutDevice"/ {
                if (match($0, /\/dev\/cu\.[^"]+/)) {
                    print substr($0, RSTART, RLENGTH)
                    exit
                }
            }
        '
        ;;
    Linux)
        # udev creates stable /dev/serial/by-id/ symlinks.
        # CH340 = "1a86" (DevKitC-1) -- check first.
        for path in /dev/serial/by-id/usb-1a86_*; do
            [ -e "$path" ] || continue
            echo "$path"
            exit
        done
        # Fallback: ESP32-S3 native USB bootloader (Zero in BOOT+RESET mode).
        # udev names this "usb-Espressif_USB_JTAG_serial_debug_unit_*" or
        # "usb-303a_1001_*" depending on the kernel/udev version.
        for path in /dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_* \
                    /dev/serial/by-id/usb-303a_1001_*; do
            [ -e "$path" ] || continue
            echo "$path"
            exit
        done
        ;;
    *)
        # Other OSes (Windows under WSL, BSDs, ...): let PlatformIO auto-detect.
        ;;
esac
