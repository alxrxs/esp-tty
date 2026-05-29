/*
 * usb_cdc_boot_trigger.h -- magic-sequence detector for USB CDC RX stream
 *
 * Purpose: provide an out-of-band, USB-only recovery path back into the
 * ROM serial bootloader when the device is otherwise unreachable.
 *
 * Threat model
 * ------------
 * The trigger is intentionally available ONLY on the device's USB CDC RX
 * pipe.  Anyone able to send these bytes already has a USB cable plugged
 * into the device -- i.e. already has physical access and could remove
 * the device entirely.  We deliberately do NOT expose this over SSH or
 * any network path: a network-reachable "reboot to download mode" is an
 * unauthenticated brick primitive and not worth the convenience.
 *
 * On match, the USB CDC RX handler posts a flag to a deferred FreeRTOS
 * task.  That task registers a shutdown handler via esp_register_shutdown_handler(),
 * calls tinyusb_driver_uninstall() to cleanly tear down the USB stack, then
 * calls esp_restart().  The shutdown handler (not the task itself) writes the
 * persistence flags: chip_usb_set_persist_flags(USBDC_BOOT_DFU) AND the
 * RTC_CNTL_OPTION1_REG / RTC_CNTL_FORCE_DOWNLOAD_BOOT bit.  This two-step
 * ordering is required because esp_restart() flushes shutdown handlers before
 * resetting the chip; writing the flag inside a shutdown handler guarantees it
 * survives the reset even though the USB stack has already been torn down.
 * See esp-idf issue #9826 for the persistence-flag rationale.  The ROM
 * bootloader honours the flag on the next reset and stays in USB-Serial-JTAG
 * download mode regardless of GPIO0 state -- the BOOT button is not required.
 *
 * Stream guarantees
 * -----------------
 * The matcher is fed every byte that arrives on the CDC RX endpoint.
 * The same byte stream is forwarded to the SSH session host-console
 * pipe; the trigger does NOT consume bytes from the stream (so an
 * accidental match still flows through to the host as data).  In
 * practice the magic sequence is designed to never appear in normal
 * UART console traffic.
 *
 * Magic-sequence design
 * ---------------------
 * The magic is bracketed by '\n' bytes so the body contains no '\n'.
 * This lets the matcher use a simple "reset to 1 if current byte is the
 * start byte, else reset to 0" recovery on mismatch -- no KMP table
 * needed.  Callers may treat the contents as opaque; only the length
 * and the public `usb_cdc_boot_trigger_magic()` view are stable.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a pointer to the magic byte sequence.  Read-only.  Length is
 * usb_cdc_boot_trigger_magic_len().  Exposed mostly so tests can
 * exercise the exact sequence without duplicating it. */
const uint8_t *usb_cdc_boot_trigger_magic(void);
size_t         usb_cdc_boot_trigger_magic_len(void);

typedef struct {
    size_t matched;
} usb_cdc_boot_trigger_t;

void usb_cdc_boot_trigger_init(usb_cdc_boot_trigger_t *s);

/* Feed one byte of CDC RX traffic.  Returns true exactly once on the
 * byte that completes the magic sequence; subsequent calls return
 * false until another full magic arrives.  The matcher is reset to
 * empty on every match. */
bool usb_cdc_boot_trigger_feed(usb_cdc_boot_trigger_t *s, uint8_t b);

#ifdef __cplusplus
}
#endif
