/*
 * usb_cdc_drain.c -- platform-agnostic CDC RX FIFO drain loop
 *
 * No ESP-IDF / TinyUSB dependencies; only ring + scrollback (both have
 * native pthread-backed implementations under RING_NATIVE / UNIT_TEST).
 */

#include "usb_cdc_drain.h"

#include <limits.h>

/* Match the original tinyusb_cdcacm_read chunk size used in cdc_rx_callback. */
#define USB_CDC_DRAIN_BUF 64

int usb_cdc_drain(usb_cdc_drain_read_fn read_fn, void *ctx,
                  ring_t *ring, scrollback_t *scrollback)
{
    return usb_cdc_drain_ex(read_fn, ctx, ring, scrollback,
                            NULL, NULL, NULL);
}

int usb_cdc_drain_ex(usb_cdc_drain_read_fn read_fn, void *ctx,
                     ring_t *ring, scrollback_t *scrollback,
                     usb_cdc_boot_trigger_t *trigger,
                     usb_cdc_drain_on_boot_trigger_fn on_match,
                     void *on_match_ctx)
{
    if (!read_fn) return -1;

    uint8_t buf[USB_CDC_DRAIN_BUF];
    /* Use size_t internally to avoid signed-integer overflow UB on
     * long-running drains (~2GB+ of CDC traffic).  Clamp to INT_MAX
     * when returning so the caller-visible `int` contract is preserved. */
    size_t total = 0;

    while (1) {
        size_t rxd = 0;
        int err = read_fn(ctx, buf, sizeof(buf), &rxd);
        if (err < 0) return -1;            /* read error -- report to caller */
        if (rxd == 0) break;               /* clean end: no more data */

        /* Capture into scrollback before the ring -- works even when no SSH
         * client is connected and the ring is full. */
        if (scrollback) {
            scrollback_push(scrollback, buf, rxd);
        }

        /* Non-blocking ring send; data drops if the ring is full or closed. */
        if (ring) {
            (void)ring_try_send(ring, buf, rxd);
        }

        /* Boot-trigger detection: byte-by-byte scan after the bulk
         * pushes so a triggering byte still reaches scrollback/ring
         * before the reset.  on_match may not return (the production
         * callback calls esp_restart()), so do this last. */
        if (trigger) {
            for (size_t i = 0; i < rxd; i++) {
                if (usb_cdc_boot_trigger_feed(trigger, buf[i])) {
                    if (on_match) on_match(on_match_ctx);
                }
            }
        }

        /* Saturating add: if we would overflow size_t or exceed INT_MAX,
         * pin to INT_MAX -- the caller (cdc_rx_callback) ignores the
         * return value, so saturation is safe.  Documented in the header. */
        if (rxd > (size_t)INT_MAX - total) {
            total = (size_t)INT_MAX;
        } else {
            total += rxd;
        }
    }

    return (total > (size_t)INT_MAX) ? INT_MAX : (int)total;
}
