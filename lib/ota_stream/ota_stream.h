/*
 * ota_stream.h — streaming "read-all" accumulator for OTA image transfer.
 *
 * Extracted from main/ota_session.c so the same growable-buffer / transient-
 * retry logic can be unit-tested natively without wolfSSH or ESP-IDF.
 *
 * The library is plain C — no ESP-IDF, no wolfSSH includes.  The caller
 * supplies:
 *   - a read callback (with a void* ctx) that returns bytes-read / 0 /
 *     <0, mirroring the wolfSSH_stream_read convention with WS_WANT_READ
 *     translated to "0 = transient" by the caller's adapter.
 *   - optional alloc / realloc / free hooks so production code can place
 *     the buffer in PSRAM (heap_caps_*) and tests can inject failures.
 *
 * Allocation strategy:
 *   - Start with a 4 KiB allocation on the first non-zero read.
 *   - Double capacity each grow.
 *   - Cap each grow at max_bytes; abort with TOOBIG if the next read would
 *     overflow that cap.
 *
 * Error semantics:
 *   - read_fn returning <0 before any bytes were stored → OTA_STREAM_ERR_EMPTY
 *     (we never allocated, *out_buf stays NULL).
 *   - read_fn returning 0 more than `max_zero_retries` times in a row
 *     (without any intervening progress) → treated as EOF.  If no bytes
 *     were ever read → OTA_STREAM_ERR_EMPTY; otherwise success.
 *   - alloc / realloc returning NULL → OTA_STREAM_ERR_OOM; the partial
 *     buffer is freed via free_fn before returning.
 *   - max_bytes exceeded → OTA_STREAM_ERR_TOOBIG; partial buffer freed.
 *
 * On any error path *out_buf is set to NULL and *out_len to 0.  On success
 * the caller owns *out_buf and must release it with the matching free_fn
 * (or plain free() if none was supplied).
 */

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Read-callback type.  Returns:
 *   > 0 : bytes read into buf
 *   0   : transient (no data yet) — caller should retry (think WS_WANT_READ)
 *   < 0 : terminal error / EOF
 */
typedef int (*ota_stream_read_fn)(void *ctx, uint8_t *buf, size_t cap);

typedef enum {
    OTA_STREAM_OK         = 0,
    OTA_STREAM_ERR_EOF    = -1,  /* read returned <0 before any bytes      */
    OTA_STREAM_ERR_OOM    = -2,  /* allocator returned NULL                 */
    OTA_STREAM_ERR_EMPTY  = -3,  /* read returned 0 bytes total, then EOF   */
    OTA_STREAM_ERR_TOOBIG = -4,  /* exceeded max_bytes                      */
} ota_stream_result_t;

/*
 * Allocator hooks.  Pass NULL to use calloc / realloc / free.
 *   - alloc_fn   : called once for the initial buffer.  Treated like calloc;
 *                  zero-init is NOT required by the implementation.
 *   - realloc_fn : called for each grow.  Standard realloc semantics:
 *                  preserves existing contents on success, returns NULL on
 *                  failure (and the old pointer is still valid).
 *   - free_fn    : used for cleanup on every error path AND, importantly,
 *                  if the caller wants to release the returned buffer they
 *                  must use the same free_fn (or plain free() if NULL).
 */
typedef void *(*ota_stream_alloc_fn)(size_t size);
typedef void *(*ota_stream_realloc_fn)(void *ptr, size_t size);
typedef void  (*ota_stream_free_fn)(void *ptr);

/*
 * Read everything from `read_fn` into a freshly-allocated buffer that grows
 * geometrically.
 *
 *   max_bytes        : hard cap on total bytes accumulated.  Crossing it
 *                      triggers OTA_STREAM_ERR_TOOBIG.
 *   max_zero_retries : how many consecutive 0-returns to tolerate before
 *                      treating the stream as ended.  0 means "treat first
 *                      0-return as EOF".
 *
 * On OTA_STREAM_OK: *out_buf is allocated, *out_len is the byte count.
 * On any error    : *out_buf is freed (and set NULL), *out_len = 0.
 */
ota_stream_result_t ota_stream_read_all(
    ota_stream_read_fn read_fn, void *ctx,
    size_t max_bytes,
    unsigned max_zero_retries,
    ota_stream_alloc_fn   alloc_fn,
    ota_stream_realloc_fn realloc_fn,
    ota_stream_free_fn    free_fn,
    uint8_t **out_buf, size_t *out_len);

#ifdef __cplusplus
}
#endif
