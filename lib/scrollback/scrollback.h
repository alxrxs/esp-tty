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

#ifdef __cplusplus
}
#endif
