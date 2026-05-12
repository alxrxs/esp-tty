# lib/scrollback — USB output capture and SSH replay buffer

This module maintains a circular byte buffer that continuously captures all
output arriving from the USB CDC device, even when no SSH client is connected.
When a new SSH session begins, `ssh_server.c` replays the most recent lines of
captured output before handing the channel over to live data, so the user
immediately sees recent device output such as kernel panics, boot logs, or crash
backtraces that arrived in the interim.  The default capacity is 128 KB
(`SCROLLBACK_DEFAULT_CAP`), sized for roughly 1600 lines at 80 characters each,
and the default replay depth is 1000 lines (`SCROLLBACK_DEFAULT_LINES`).

## Files

- **scrollback.h** — public interface.  Declares the opaque `scrollback_t`
  type, the four primary API functions, the two pure formatting helpers, and the
  `SCROLLBACK_FOOTER` string constant.
- **scrollback.c** — implementation.  The pure formatters and the
  `SCROLLBACK_FOOTER` definition are compiled unconditionally on both targets.
  The circular-buffer implementation is selected by an `#ifdef UNIT_TEST` guard:
  on ESP32 targets the struct uses a FreeRTOS `SemaphoreHandle_t` and allocates
  its backing store with `heap_caps_malloc(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)`
  (falling back to internal RAM when PSRAM is unavailable, e.g. under Wokwi);
  on native test builds the same struct layout uses a `pthread_mutex_t` and
  plain `malloc`, following the same dual-backend pattern as `lib/ring/ring.c`.

## API

- `scrollback_create(cap)` — allocate a new buffer with `cap` bytes of circular
  storage.  Returns `NULL` on allocation failure.
- `scrollback_push(sb, data, len)` — append bytes to the ring, overwriting the
  oldest content once the buffer is full.  Non-blocking; safe to call from the
  TinyUSB CDC RX callback context.  On ESP32 the lock is held only for the
  duration of the `memcpy` (at most 64 bytes per CDC chunk), so contention is
  at the microsecond level.
- `scrollback_get_lines(sb, max_lines, &out_len)` — allocate and return a
  linearised copy of the last `max_lines` newline-delimited lines stored in the
  buffer.  Scans backward through the ring without holding the lock (a brief
  lock is taken only to snapshot the mutable `head` and `used` fields), so minor
  tearing under concurrent pushes is accepted as a trade-off in this
  debug-replay path.  Returns `NULL` when the buffer is empty or allocation
  fails; the caller must `free()` the returned pointer.
- `scrollback_count_newlines(buf, len)` — pure function; counts `'\n'` bytes in
  an arbitrary buffer.  Returns 0 for NULL or zero-length input.  Used by the
  SSH replay path to report the line count in the header.
- `scrollback_format_header(line_count, out, out_sz)` — pure function; formats
  the dimmed ANSI banner `"\r\n\x1b[2m--- scrollback: N lines ---\x1b[0m\r\n"`
  into a caller-supplied buffer.  Returns the byte count written (excluding the
  NUL), or 0 if `line_count` is negative, `out` is NULL, or `out_sz` is too
  small for the formatted string plus its NUL terminator.  A 64-byte buffer is
  comfortable for counts up to six digits.
- `SCROLLBACK_FOOTER` — the fixed string `"\x1b[2m--- live ---\x1b[0m\r\n"`
  emitted after the replay dump to mark the boundary between historical and live
  output.

## Usage in the firmware

`usb_cdc.c` passes the `scrollback_t *` pointer into `usb_cdc_drain()` on every
CDC RX callback; the drain helper calls `scrollback_push()` for each received
chunk, keeping the ring current at all times.  In `ssh_server.c`, immediately
after wolfSSH authentication succeeds, the session-start path calls
`scrollback_get_lines()`, formats the banner with `scrollback_format_header()`
and `scrollback_count_newlines()`, streams the historical bytes via
`wolfSSH_stream_send()`, and appends `SCROLLBACK_FOOTER` before unblocking the
live bridge pump tasks.

## Native testability

`scrollback_count_newlines` and `scrollback_format_header` have no platform
dependencies and are compiled identically on both targets.  The circular-buffer
operations use the `pthread`-backed native implementation under `UNIT_TEST`.
`test/native/test_scrollback/test_scrollback.c` exercises all three layers with
26 Unity cases: basic construction, empty-buffer semantics, push-then-get
round-trips, wrap-around overflow, backward line scanning, cross-boundary line
retrieval, zero-`max_lines` edge case, multi-push accumulation, newline counting
across NULL/empty/binary/CRLF inputs, header formatting for valid and invalid
inputs (negative count, NULL output pointer, undersized buffer, exact-fit
boundary), and the `SCROLLBACK_FOOTER` string value.
