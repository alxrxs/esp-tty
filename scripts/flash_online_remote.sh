#!/bin/bash
# flash_online_remote.sh -- runs on the remote host that owns the USB cable.
#
# Invoked by `make flash-online <dev>` after the build artifacts have been
# tarred over.  Picks the right flash method based on the env name:
#
#   *_debug envs  -- USB_DEBUG_CONSOLE_ONLY=y, no TinyUSB.  Chip enumerates
#                    as the ESP32-S3's native USB-Serial-JTAG (303a:1001).
#                    esptool's --before default-reset works directly.
#
#   non-debug     -- TinyUSB CDC is active (303a:xxxx).  esptool's
#                    pyserial-based RTS reset hits EPROTO on TinyUSB.
#                    Use the boot-trigger magic to enter ROM USB DFU
#                    (303a:0009), then dfu-util -R writes flash + resets.
#
# Args:
#   $1 = ENV name (e.g. esp32s3_zero, esp32s3_debug)
#   $2 = directory containing the build artifacts (bootloader.bin,
#        partitions.bin, ota_data_initial.bin, firmware.bin, and for
#        non-debug envs also firmware.dfu)
#   $3 = serial port (default /dev/ttyACM0)
set -eu

ENV="${1:?env required}"
BIN_DIR="${2:?bin-dir required}"
PORT="${3:-/dev/ttyACM0}"

# Magic sequence -- must stay byte-for-byte identical to k_magic[] in
# lib/usb_cdc_boot_trigger/usb_cdc_boot_trigger.c.  Built via printf to
# avoid bash-vs-sh quoting differences in $'...' C-escape interpretation.
MAGIC_BODY='ESPTTY_REBOOT_TO_BOOTLOADER_xK9w7Pq3J8dHvR_NOW'

case "$ENV" in
  *_debug)
    # Debug build: native USB-Serial-JTAG, esptool works directly.
    echo "[flash-online] env=$ENV -- esptool via USB-Serial-JTAG ($PORT)"
    esptool --port "$PORT" --chip esp32s3 \
        --before default-reset --after hard-reset write-flash \
        0x0     "$BIN_DIR/bootloader.bin" \
        0x8000  "$BIN_DIR/partitions.bin" \
        0x10000 "$BIN_DIR/ota_data_initial.bin" \
        0x20000 "$BIN_DIR/firmware.bin"
    ;;
  *)
    # Non-debug build: send the magic, wait for ROM DFU re-enumeration,
    # then dfu-util writes + resets.  The whole sequence runs without any
    # physical access to the device.
    if [ ! -f "$BIN_DIR/firmware.dfu" ]; then
      echo "[flash-online] error: $BIN_DIR/firmware.dfu missing" >&2
      exit 2
    fi

    echo "[flash-online] env=$ENV -- magic + dfu-util via TinyUSB ($PORT)"
    if [ ! -e "$PORT" ]; then
      echo "[flash-online] error: $PORT does not exist on this host" >&2
      exit 2
    fi
    # Sanity-check that $PORT actually belongs to the running esp-tty
    # TinyUSB endpoint -- not e.g. a CH340 USB-UART that happens to be
    # /dev/ttyACM0 on this host.  The CDC RX boot-trigger matcher only
    # runs in the ESP32-S3 firmware, so writing the magic to a CH340
    # bridge would simply forward the bytes to the target's UART and
    # never reboot the chip.
    #
    # udev's stable by-id symlinks encode the VID:PID; resolve $PORT to
    # its real device node and walk up to the USB device's idVendor.
    real_port=$(readlink -f "$PORT" 2>/dev/null || echo "$PORT")
    syspath=$(udevadm info -q path -n "$real_port" 2>/dev/null || true)
    if [ -n "$syspath" ]; then
        vid=$(udevadm info -a -p "$syspath" 2>/dev/null \
              | awk -F'==' '/ATTRS{idVendor}/ {gsub(/"/,"",$2); print $2; exit}')
        if [ -n "$vid" ] && [ "$vid" != "303a" ]; then
            echo "[flash-online] error: $PORT has USB VID $vid, expected 303a" >&2
            echo "[flash-online]   (looks like a USB-UART bridge, not the" >&2
            echo "[flash-online]    ESP32-S3 TinyUSB CDC).  Re-run with" >&2
            echo "[flash-online]    REMOTE_PORT=/dev/serial/by-id/usb-*_303a_*" >&2
            exit 2
        fi
    fi
    stty -F "$PORT" raw -echo -hupcl 115200
    # \n + body + \n -- printf builds the bytes directly, no $'...' needed.
    printf '\n%s\n' "$MAGIC_BODY" > "$PORT"

    # Wait up to 6 seconds for the chip to re-enumerate as 303a:0009.
    echo "[flash-online] magic sent; waiting for ROM DFU endpoint..."
    for i in $(seq 1 30); do
      if lsusb -d 303a:0009 >/dev/null 2>&1; then break; fi
      sleep 0.2
    done
    if ! lsusb -d 303a:0009 >/dev/null 2>&1; then
      echo "[flash-online] error: 303a:0009 (ROM DFU) did not appear" >&2
      exit 3
    fi

    # dfu-util commonly reports "can't detach" on the post-download reset
    # because by then the chip is gone -- which is precisely the success
    # signal we wanted.  Treat the combination "Download done." + "Resetting
    # USB" as success regardless of dfu-util's own exit code.
    #
    # LC_ALL=C pins dfu-util's stdout to English so the grep below works
    # on remote hosts with a localised locale (e.g. de_DE: "Fertig.").
    set +e
    dfu_out=$(LC_ALL=C dfu-util -d 0x303a:0x0009 -a 0 -R \
                       -D "$BIN_DIR/firmware.dfu" 2>&1)
    dfu_rc=$?
    set -e
    echo "$dfu_out" | tail -5
    if echo "$dfu_out" | grep -q 'Download done\.' && \
       echo "$dfu_out" | grep -q 'Resetting USB'; then
        echo "[flash-online] dfu-util write+reset complete (rc=$dfu_rc treated as OK)"
        exit 0
    fi
    echo "[flash-online] dfu-util failed (rc=$dfu_rc)" >&2
    exit "$dfu_rc"
    ;;
esac
