/*
 * usb_cdc_drain.h -- host-testable USB CDC RX FIFO drain loop
 *
 * Extracted from the TinyUSB CDC RX callback so the loop can be unit-tested
 * on the native host without ESP-IDF / TinyUSB present.
 *
 * The drain helper repeatedly invokes a caller-supplied read function until
 * it reports "no more data" (rxd == 0) or returns an error.  Each chunk is
 * pushed to a scrollback (best-effort, captures even when no SSH client is
 * connected) and then attempted into a ring via the non-blocking
 * ring_try_send (data is dropped if the ring is full or closed).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "ring.h"
#include "scrollback.h"
#include "usb_cdc_boot_trigger.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Called per byte-stream match of the boot-trigger magic.  Receives
 * the user context passed to usb_cdc_drain_ex().  May be NULL. */
typedef void (*usb_cdc_drain_on_boot_trigger_fn)(void *ctx);

/*
 * Read function type -- abstracts tinyusb_cdcacm_read for testability.
 * Returns 0 on success (writing rxd bytes to buf); negative on error.
 * Writing rxd == 0 with success means "no more data" (terminates the drain).
 */
typedef int (*usb_cdc_drain_read_fn)(void *ctx, uint8_t *buf, size_t cap,
                                     size_t *rxd);

/*
 * Drain the read source until it reports empty (rxd == 0) or an error.
 *
 * Each successfully-read chunk is first pushed to scrollback (best-effort),
 * then attempted into the ring via ring_try_send (non-blocking -- bytes that
 * don't fit are dropped).
 *
 * Return-value convention:
 *   - On clean termination (read_fn returned success with rxd == 0): returns
 *     the total number of bytes drained from the source (>= 0).
 *   - On read_fn error: returns -1.  Any chunks read successfully before the
 *     error are still pushed to scrollback/ring; only the error is reported.
 *
 * The reported count is "bytes drained from the source", not "bytes pushed
 * into the ring" -- the ring may drop bytes silently when full, but the
 * scrollback (best-effort) and the source itself are always advanced.
 *
 * scrollback may be NULL (no scrollback capture).  ring may be NULL too.
 */
int usb_cdc_drain(usb_cdc_drain_read_fn read_fn, void *ctx,
                  ring_t *ring, scrollback_t *scrollback);

/*
 * Extended drain: same as usb_cdc_drain(), but each byte is also fed to
 * the supplied boot-trigger matcher.  When the matcher fires (i.e. the
 * USB CDC RX magic sequence has been received in full), on_match is
 * invoked with on_match_ctx.  Bytes are NOT consumed -- they still
 * flow to scrollback and the ring as normal.
 *
 * trigger may be NULL (no matching; behaves identical to usb_cdc_drain).
 * on_match may be NULL (matches detected silently and the count is
 * still reflected in the bytes-drained return value).
 */
int usb_cdc_drain_ex(usb_cdc_drain_read_fn read_fn, void *ctx,
                     ring_t *ring, scrollback_t *scrollback,
                     usb_cdc_boot_trigger_t *trigger,
                     usb_cdc_drain_on_boot_trigger_fn on_match,
                     void *on_match_ctx);

#ifdef __cplusplus
}
#endif
