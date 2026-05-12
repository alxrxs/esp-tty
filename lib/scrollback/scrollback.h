/*
 * scrollback.h — Circular byte buffer that captures USB device output
 *
 * Written continuously by the USB CDC callback (even with no SSH client
 * connected), then replayed to each SSH client when it connects.
 *
 * Backed by PSRAM on ESP32 targets; no-op stubs on UNIT_TEST builds.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scrollback_t scrollback_t;

/* Default capacity: 128 KB ≈ 1600 lines at 80 chars/line */
#define SCROLLBACK_DEFAULT_CAP   (128u * 1024u)

/* Lines to replay to each newly-connected SSH client */
#define SCROLLBACK_DEFAULT_LINES 1000

scrollback_t *scrollback_create(size_t cap);

/*
 * Append data to the scrollback ring, overwriting the oldest bytes once
 * the buffer is full.  Non-blocking; safe to call from TinyUSB callback
 * context.  Silently skips if the lock is momentarily held by a dump.
 */
void scrollback_push(scrollback_t *sb, const uint8_t *data, size_t len);

/*
 * Return a heap-allocated, linearised copy of the last max_lines lines
 * stored in the buffer.  *out_len is set to the byte count of the copy.
 * Returns NULL if the buffer is empty or memory allocation fails.
 * The caller must free() the returned pointer.
 */
uint8_t *scrollback_get_lines(scrollback_t *sb, int max_lines, size_t *out_len);

/* ── Pure formatters (no platform deps; safe for native unit tests) ───────── */

/*
 * Count the number of '\n' bytes in `buf[0 .. len)`.  Returns 0 for
 * NULL/empty input.  Used by the SSH server's replay path to report how
 * many lines of scrollback are being sent.
 */
int scrollback_count_newlines(const uint8_t *buf, size_t len);

/*
 * Format the scrollback replay header into `out`:
 *   "\r\n\x1b[2m--- scrollback: N lines ---\x1b[0m\r\n"
 *
 * Returns the number of bytes written to `out` (not counting the
 * implicit NUL), or 0 if:
 *   - line_count < 0           (caller passed a bogus value)
 *   - out is NULL
 *   - out_sz is too small for the formatted string + NUL
 *
 * Always NUL-terminates `out` when it returns > 0.  For typical line
 * counts (1–4 digits) the result is < 50 bytes; 64 is comfortable.
 */
int scrollback_format_header(int line_count, char *out, size_t out_sz);

/*
 * Fixed footer emitted after the scrollback dump, just before live
 * data begins.  Defined in scrollback.c.
 */
extern const char SCROLLBACK_FOOTER[];

#ifdef __cplusplus
}
#endif
