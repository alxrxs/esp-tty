# lib/bridge -- byte-pump core

This module contains the single function `bridge_pump()`, which copies bytes
from an abstract source to an abstract sink until a stop flag is set or either
callback signals an error. It has no dependencies on ESP-IDF, FreeRTOS, wolfSSH,
or any other platform library -- only `<stdint.h>`, `<stddef.h>`, and
`<stdbool.h>`.

## Files

- **bridge.h** -- public interface. Declares the `bridge_read_fn` and
  `bridge_write_fn` function-pointer typedefs (both take an opaque `void *ctx`)
  and the `bridge_pump()` signature. The header also documents the intended
  call sites: the SSH task runs two concurrent `bridge_pump()` instances, one
  for each direction (SSH->USB and USB->SSH).
- **bridge.c** -- implementation. Allocates a 4096-byte stack buffer, loops
  calling the read callback then the write callback, and exits when `*stop` is
  true (checked at the top of each iteration) or either callback returns `<= 0`.

## Usage in the firmware

`ssh_server.c` wires two `bridge_pump()` calls in dedicated FreeRTOS tasks:
one pair of callbacks wraps wolfSSH channel reads/writes and the other wraps
USB CDC ACM reads/writes, with the ring buffers in PSRAM acting as the
transport between the two sides.

## Native testability

Because the module is free of platform dependencies it compiles and runs on the
host. `test/native/test_bridge/test_bridge.c` exercises it via Unity with five
cases: lossless in-order transfer of 64 KB through a 512-byte ring,
stop-flag termination, full-duplex no-drop transfer of 128 KB through a 256-byte
ring, termination on a write-callback error, and verification that the stop flag
is observed before the next read call rather than mid-iteration.
