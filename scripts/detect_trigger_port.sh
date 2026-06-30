#!/bin/sh
# detect_trigger_port.sh -- print the device node of the *running* esp-tty
# TinyUSB CDC endpoint.
#
# This is the port scripts/reboot_to_bootloader.py writes the USB-CDC
# boot-trigger magic to, so `make flash-online` can drop the chip into ROM USB
# DFU (303a:0009) without a physical BOOT+EN press.
#
# We match by the ESP32-S3 native-USB Vendor ID (0x303A) while EXCLUDING the
# two ROM PIDs that are NOT the running app:
#   0x1001  USB-Serial-JTAG / ROM bootloader  (no app running, or a *_debug build)
#   0x0009  ROM USB DFU                        (chip already in download mode)
# Any other 0x303A PID is the running TinyUSB CDC -- 0x4001 in the example
# config; a deployment may pick any value (USB_PID is configurable in config.h).
#
# Why not glob /dev/serial/by-id/ ?  This firmware sets its own USB string
# descriptors (manufacturer/product), so udev names the by-id node after those
# strings -- it carries NO "_303a_<pid>_" substring to match on.  Ironically the
# ROM PIDs (the ones we want to exclude) are the only ones that get a VID:PID-form
# by-id name.  So we ask the kernel for the actual idVendor/idProduct instead.
#
# Prints nothing if no such endpoint is found; the Makefile then errors and asks
# for an explicit override.  Override at any time with:
#   make flash-online TRIG_PORT=/dev/...

case "$(uname -s)" in
    Linux)
        for dev in /dev/ttyACM* /dev/ttyUSB*; do
            [ -e "$dev" ] || continue
            sys="/sys/class/tty/${dev#/dev/}/device"
            [ -e "$sys" ] || continue
            # Walk up the sysfs tree from the CDC interface to the USB device
            # node -- the first ancestor that carries idVendor/idProduct.
            node=$(readlink -f "$sys")
            vid= ; pid=
            while [ -n "$node" ] && [ "$node" != "/" ]; do
                if [ -r "$node/idVendor" ] && [ -r "$node/idProduct" ]; then
                    vid=$(cat "$node/idVendor")
                    pid=$(cat "$node/idProduct")
                    break
                fi
                node=$(dirname "$node")
            done
            [ "$vid" = "303a" ] || continue
            case "$pid" in 1001|0009) continue ;; esac
            echo "$dev"
            exit 0
        done
        ;;
    Darwin)
        # macOS: walk the IOUSBHostDevice tree for VID 0x303A (12346) with a
        # PID that is neither 0x1001 (4097) nor 0x0009 (9), then grab its first
        # IOCalloutDevice (/dev/cu.*).
        ioreg -r -c IOUSBHostDevice -l 2>/dev/null | awk '
            /IOUSBHostDevice/ { in_dev = 1; vid = 0; pid = 0; is_target = 0 }
            in_dev && /"idVendor" = /  { vid = $NF + 0 }
            in_dev && /"idProduct" = / { pid = $NF + 0 }
            in_dev && vid == 12346 && pid != 0 && pid != 4097 && pid != 9 {
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
    *)
        # Other OSes (WSL, BSDs, ...): no autodetect -- pass TRIG_PORT=... .
        ;;
esac
