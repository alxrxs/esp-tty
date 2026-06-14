/*
 * ring.h -- thin StreamBuffer wrapper with a host-testable interface
 *
 * On ESP32 targets, backed by FreeRTOS xStreamBufferCreateWithCaps (PSRAM).
 * On native (test) targets, backed by pthread mutex + condvar.
 *
 * Contract:
 *   - Exactly one writer and one reader per ring instance.
 *   - ring_send() blocks until all bytes are written (backpressure).
 *   - ring_recv() blocks until at least one byte is available.
 *   - ring_free() must not be called while any task is blocked on the ring.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ring ring_t;

/* Allocate a ring with the given capacity (bytes). Returns NULL on failure. */
ring_t *ring_create(size_t capacity);

/* Release memory.  Caller must ensure no tasks are blocked on the ring. */
void ring_free(ring_t *r);

/*
 * Write exactly len bytes into the ring.
 * Blocks indefinitely until all bytes are accepted (backpressure).
 * Returns len on success, -1 if the ring has been closed.
 */
int ring_send(ring_t *r, const uint8_t *buf, size_t len);

/*
 * Read up to cap bytes from the ring into buf.
 * Blocks until at least one byte is available.
 * Returns the number of bytes read (>= 1), or -1 if the ring is closed.
 * Returns 0 immediately (without blocking) when cap == 0.
 */
int ring_recv(ring_t *r, uint8_t *buf, size_t cap);

/*
 * Signal the ring as closed.  Ongoing and future ring_send / ring_recv
 * calls return -1 once the ring is closed.
 */
void ring_close(ring_t *r);

/*
 * Re-open a previously closed ring so it can be reused for a new session.
 * Drains any stale data remaining from the old session.
 *
 * The drain reads from the ring, so this MUST NOT be called while any other
 * task is reading the same ring (the underlying FreeRTOS StreamBuffer permits
 * only a single concurrent reader -- a second receiver can corrupt its tail
 * index).  Use this only for the direction whose reader is a per-session pump
 * task that has already exited by reopen time.  For a ring with a long-lived
 * reader (e.g. an always-running TX task), use ring_reopen_keep_data().
 */
void ring_reopen(ring_t *r);

/*
 * Re-open a previously closed ring WITHOUT draining it.
 *
 * Clears the closed flag only; leaves any buffered bytes in place.  Because it
 * never reads from the ring, it is safe to call even while the ring's
 * long-lived reader is concurrently blocked in ring_recv -- preserving the
 * single-reader invariant the FreeRTOS StreamBuffer requires.
 *
 * Intended for the ssh_to_usb direction, whose reader (usb_tx_task) runs for
 * the lifetime of the process: any leftover bytes are benign console output
 * that the reader will simply forward to USB.
 */
void ring_reopen_keep_data(ring_t *r);

/*
 * Non-blocking variant of ring_send.
 * Writes as many bytes as currently fit without blocking.
 * Returns the number of bytes successfully written (0 .. len).
 * Returns -1 if the ring is closed.
 * Never blocks -- safe to call from interrupt-adjacent contexts (e.g. TinyUSB
 * CDC RX callback).
 */
int ring_try_send(ring_t *r, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
