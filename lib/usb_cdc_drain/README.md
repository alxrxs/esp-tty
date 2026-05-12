# lib/usb_cdc_drain -- TinyUSB CDC RX FIFO drain loop

This module provides `usb_cdc_drain()`, a platform-agnostic helper that reads
a CDC ACM receive source to exhaustion. The function takes a caller-supplied
`usb_cdc_drain_read_fn` function pointer (plus an opaque `void *ctx`) and loops
on it, 64 bytes at a time, until the read function reports no more data
(`rxd == 0`) or returns an error. Each chunk is forwarded to a scrollback buffer
(best-effort, for terminal replay) and then attempted into a ring via
`ring_try_send` (non-blocking -- bytes that do not fit are dropped silently). The
indirection through `read_fn` keeps TinyUSB out of the compilation unit, so the
loop can be exercised by native host tests without any ESP-IDF or TinyUSB
headers present.

## Why this exists -- the agetty wedge bug

`cdc_rx_callback` originally called `tinyusb_cdcacm_read` once per invocation
and returned. The TinyUSB CDC RX FIFO is 512 bytes (`CONFIG_TINYUSB_CDC_RX_BUFSIZE`),
but each call to `tinyusb_cdcacm_read` returns at most one USB packet -- 64 bytes.
When the host wrote a burst larger than 64 bytes (agetty writing `/etc/issue` is
roughly 301 bytes), the callback drained only the first chunk and exited; the
remainder sat in the FIFO. With the FIFO full, TinyUSB began NAKing new CDC OUT
transfers. The Linux host's `n_tty_write` blocks until the NAK clears, so agetty
wedged mid-banner and never displayed the login prompt. The fix is for the
callback to loop until `tinyusb_cdcacm_read` returns `rxd == 0`, which is exactly
what `usb_cdc_drain()` does. The loop was extracted into this library so the
fix could be verified by unit tests without hardware.

## API

```c
typedef int (*usb_cdc_drain_read_fn)(void *ctx, uint8_t *buf, size_t cap,
                                     size_t *rxd);

int usb_cdc_drain(usb_cdc_drain_read_fn read_fn, void *ctx,
                  ring_t *ring, scrollback_t *scrollback);
```

Return-value convention: on clean termination (`read_fn` returned success with
`rxd == 0`) the function returns the total number of bytes drained from the
source (>= 0). On a `read_fn` error it returns -1; any chunks successfully
read before the error are still forwarded to scrollback and the ring. The count
reflects bytes consumed from the source, not bytes accepted by the ring -- the
ring may drop silently when full or closed, but that does not affect the return
value. Both `ring` and `scrollback` may be NULL.

## Usage in the firmware

`main/usb_cdc.c` defines a thin adapter, `tinyusb_read_adapter`, that matches
the `usb_cdc_drain_read_fn` signature and wraps `tinyusb_cdcacm_read`. The CDC
RX callback passes this adapter (with the interface index smuggled through `ctx`)
to `usb_cdc_drain` along with the `usb_to_ssh` ring and the global scrollback.

## Tests

Six cases in `test/native/test_cdc_drain/test_cdc_drain.c`, compiled with
`-DRING_NATIVE -DUNIT_TEST`. The test suite uses a scripted stub (`scripted_read_cb`)
that returns a preset sequence of chunk sizes or errors, and verifies: clean
multi-chunk drain with correct byte counts in ring and scrollback; single
sub-64-byte chunk; termination on read error with pre-error bytes preserved;
continued draining when the ring is full (partial write); continued draining
when the ring is already closed; and immediate termination when the first call
returns zero bytes.
