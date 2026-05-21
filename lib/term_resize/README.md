# lib/term_resize -- xterm "set window size" CSI formatter

This module contains the single function `term_resize_format()`, which formats
the xterm `\033[8;<rows>;<cols>t` CSI sequence into a caller-supplied buffer.
When wolfSSH receives a `SSH_MSG_CHANNEL_REQUEST` with request type
`window-change`, the `term_resize_cb` in `ssh_server.c` calls this function and
injects the resulting byte sequence directly into the USB-bound ring buffer.  The
Linux (or macOS) terminal driver on the host side interprets the sequence and
updates its internal geometry, keeping the remote shell in sync with the client
window.  The function has no dependencies on ESP-IDF, wolfSSH, or FreeRTOS -- only
`<stdio.h>` and `<stdint.h>` -- so it builds identically on device and on the
native test host.

The formatting logic was extracted from `term_resize_cb` precisely because it is
the only non-trivial piece in that callback: everything else is type-casting and
a single `ring_send` call.  Keeping the formatter in its own translation unit
makes the correctness guarantee drift-proof -- the unit tests cover the exact byte
strings emitted, boundary conditions (zero cols or rows, NULL buffer, undersized
buffer, exact-fit buffer), and the full `uint32_t` range -- without requiring any
mock for wolfSSH or FreeRTOS.  Any future change to the escape sequence is caught
by the test suite before reaching hardware.

## API

```c
int term_resize_format(uint32_t cols, uint32_t rows, char *out, size_t out_sz);
```

Writes `\033[8;<rows>;<cols>t` into `out` and returns the number of bytes written
(not counting the NUL terminator), or `0` if any argument is invalid: zero
dimensions, `NULL` output pointer, or a buffer too small to hold the full
sequence plus the terminating NUL.  For typical values (`cols=80, rows=24`) the
sequence is 10 bytes; a buffer of 32 bytes is comfortable for all values that
arise in practice, and 64 bytes accommodates the maximum `uint32_t` case.

## Tests

`test/native/test_term_resize/test_term_resize.c` covers the typical 80x24
case (exact byte string), the 1x1 minimum, a 500x200 large terminal, all
three zero-dimension early returns, a NULL-pointer guard, an undersized
buffer, exact-fit boundary (payload length versus payload+1), and the
`UINT32_MAX` extreme.
