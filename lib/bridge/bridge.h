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
#include <stdatomic.h>

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
 *
 * `stop` is an _Atomic bool because the producer (a separate task that
 * decides to tear down the session) and the consumer (this loop) run on
 * different FreeRTOS tasks and, on ESP32-S3, may run on different Xtensa
 * cores.  `volatile` alone provides per-CPU compiler ordering but no
 * inter-core memory ordering, so a stale `false` could be observed
 * indefinitely.  atomic_load(seq_cst) ensures cross-core visibility.
 */
void bridge_pump(bridge_read_fn  r, void *r_ctx,
                 bridge_write_fn w, void *w_ctx,
                 _Atomic bool   *stop);

#ifdef __cplusplus
}
#endif
