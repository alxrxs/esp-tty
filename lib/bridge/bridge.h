/*
 * bridge.h -- pure byte-pump logic, no ESP-IDF / FreeRTOS / wolfSSH deps
 *
 * bridge_pump() reads from one source and writes to one sink, looping
 * until *stop is set or either callback returns an error.
 *
 * The SSH task runs two bridge_pump() instances concurrently:
 *   - SSH -> USB:  r = ssh_read,  w = usb_write
 *   - USB -> SSH:  r = usb_read,  w = ssh_write
 */

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * read_fn:  fill buf[0..cap-1], return bytes read (>= 1), or <= 0 on error/EOF.
 * write_fn: write buf[0..len-1], return len on success, or <= 0 on error.
 */
typedef int (*bridge_read_fn)(void *ctx, uint8_t *buf, size_t cap);
typedef int (*bridge_write_fn)(void *ctx, const uint8_t *buf, size_t len);

/*
 * Pump bytes from r/r_ctx to w/w_ctx until *stop becomes true or either
 * callback returns an error (<=0).  Blocking -- call from a dedicated task.
 */
void bridge_pump(bridge_read_fn  r, void *r_ctx,
                 bridge_write_fn w, void *w_ctx,
                 volatile bool  *stop);

#ifdef __cplusplus
}
#endif
