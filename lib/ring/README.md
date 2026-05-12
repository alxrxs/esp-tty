# ring -- Blocking Byte Queue

A blocking, single-producer / single-reader byte queue used as the data
conduit between the USB CDC and SSH tasks. Two instances carry all traffic
across the bridge: one in each direction.

## Backends

On ESP32 targets the ring is backed by a FreeRTOS `xStreamBufferCreateWithCaps`
call that places the data region in PSRAM (`MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT`,
8 MB OPI PSRAM on the N16R8 module) while keeping the control struct in internal
SRAM, which is safe during cache-disabled flash operations. If PSRAM is absent
(e.g. the Wokwi simulator with `CONFIG_SPIRAM=n`) the create call falls back to
`xStreamBufferCreate` in internal SRAM. Blocking in `ring_send` and `ring_recv`
is implemented as a 50 ms polling timeout on the underlying StreamBuffer, which
lets `ring_close` wake both sides without requiring a separate notification path.

On native (host test) builds the `RING_NATIVE=1` preprocessor flag selects a
POSIX implementation: a heap-allocated circular byte buffer protected by a
`pthread_mutex_t` and signalled via two `pthread_cond_t` variables
(`not_full` / `not_empty`). The two backends share the same header and are
exercised by the same test suite, so semantics are verified on the host without
touching hardware.

## API

```c
ring_t *ring_create(size_t capacity);
void    ring_free(ring_t *r);

int ring_send    (ring_t *r, const uint8_t *buf, size_t len);
int ring_recv    (ring_t *r,       uint8_t *buf, size_t cap);
int ring_try_send(ring_t *r, const uint8_t *buf, size_t len);

void ring_close (ring_t *r);
void ring_reopen(ring_t *r);
```

`ring_send` blocks until all `len` bytes have been accepted, providing
backpressure. `ring_recv` blocks until at least one byte is available and
returns however many bytes it could read in one call (up to `cap`). Both
return `-1` immediately once the ring is closed.

`ring_try_send` is a non-blocking variant intended for use from the TinyUSB
CDC RX callback, which must not block. It writes as many bytes as currently
fit and returns the count (0 if the ring is full, -1 if it is closed).

`ring_close` marks the ring as closed and unblocks any tasks waiting in
`ring_send` or `ring_recv`. `ring_free` releases all memory; the caller must
ensure no tasks are still blocked on the ring before calling it.

## Concurrency contract

Each ring instance supports exactly one concurrent writer and one concurrent
reader. Calling `ring_send` from more than one task, or `ring_recv` from more
than one task, is not supported and will corrupt the buffer state.

## Session reuse with ring_reopen

When an SSH session ends, `ring_close` is called to unblock the pump tasks.
Rather than tearing down and reallocating the rings for the next session,
`ring_reopen` resets the closed flag and drains any stale bytes left from the
previous session. This avoids a PSRAM allocation on every session takeover
and is safe to call once both pump tasks have exited (i.e. no tasks are
blocked on the ring). `ring_reopen` on an already-open ring is a no-op and
does not disturb data in flight.

## Tests

17 cases in `test/native/test_ring/`. Covers FIFO ordering, wrap-around,
close-unblocks-reader, backpressure losslessness, `ring_try_send` partial
writes and contention behaviour, and all `ring_reopen` paths.
