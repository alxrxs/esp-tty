/*
 * ring.h — thin StreamBuffer wrapper with a host-testable interface
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
 */
int ring_recv(ring_t *r, uint8_t *buf, size_t cap);

/*
 * Signal the ring as closed.  Ongoing and future ring_send / ring_recv
 * calls return -1 once the ring is closed.
 */
void ring_close(ring_t *r);

#ifdef __cplusplus
}
#endif
