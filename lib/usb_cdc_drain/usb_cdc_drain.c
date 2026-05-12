/*
 * usb_cdc_drain.c -- platform-agnostic CDC RX FIFO drain loop
 *
 * No ESP-IDF / TinyUSB dependencies; only ring + scrollback (both have
 * native pthread-backed implementations under RING_NATIVE / UNIT_TEST).
 */

#include "usb_cdc_drain.h"

/* Match the original tinyusb_cdcacm_read chunk size used in cdc_rx_callback. */
#define USB_CDC_DRAIN_BUF 64

int usb_cdc_drain(usb_cdc_drain_read_fn read_fn, void *ctx,
                  ring_t *ring, scrollback_t *scrollback)
{
    if (!read_fn) return -1;

    uint8_t buf[USB_CDC_DRAIN_BUF];
    int total = 0;

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

        total += (int)rxd;
    }

    return total;
}
