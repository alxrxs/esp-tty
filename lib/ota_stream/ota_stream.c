/*
 * ota_stream.c -- implementation of ota_stream_read_all.
 *
 * See ota_stream.h for the contract.  No ESP-IDF / wolfSSH dependencies;
 * this file is dual-buildable for the ESP32-S3 firmware and the native
 * Unity test harness.
 *
 * Implementation notes:
 *   - We read directly into the tail of the grown buffer (no intermediate
 *     scratch).  This avoids an extra memcpy and avoids artificially capping
 *     the per-call read size at the scratch size.
 *   - Capacity doubles each grow, starting at OTA_STREAM_INITIAL_CAP.
 *   - The per-call "ask size" is `cap - used`; once that drops to zero we
 *     trigger another grow.  When `used` already equals max_bytes we ask
 *     for 1 more byte so a >0 return cleanly triggers TOOBIG instead of
 *     looping.
 */

#include "ota_stream.h"

#include <stdlib.h>
#include <string.h>

/* Initial buffer size -- small enough to keep RAM pressure low on the
 * empty-stream path, large enough to absorb the first few SSH chunks
 * without an immediate realloc. */
#define OTA_STREAM_INITIAL_CAP  (4u * 1024u)

static void *default_alloc(size_t n)              { return calloc(1, n); }
static void *default_realloc(void *p, size_t n)   { return realloc(p, n); }
static void  default_free(void *p)                { free(p); }

ota_stream_result_t ota_stream_read_all(
    ota_stream_read_fn read_fn, void *ctx,
    size_t max_bytes,
    unsigned max_zero_retries,
    ota_stream_alloc_fn   alloc_fn,
    ota_stream_realloc_fn realloc_fn,
    ota_stream_free_fn    free_fn,
    uint8_t **out_buf, size_t *out_len)
{
    if (!read_fn || !out_buf || !out_len) return OTA_STREAM_ERR_EOF;

    *out_buf = NULL;
    *out_len = 0;

    if (!alloc_fn)   alloc_fn   = default_alloc;
    if (!realloc_fn) realloc_fn = default_realloc;
    if (!free_fn)    free_fn    = default_free;

    uint8_t *buf      = NULL;
    size_t   used     = 0;
    size_t   cap      = 0;
    unsigned zero_run = 0;        /* consecutive transient 0-returns */

    for (;;) {
        /* Ensure we have at least one byte of headroom in the buffer
         * before issuing a read.  We always want to read directly into
         * the buffer tail so a large chunk does not get truncated by an
         * artificially-small scratch. */
        if (used >= cap) {
            /* Grow.  At cap==0 (first iteration) start at INITIAL_CAP;
             * thereafter double.  Always cap final size at max_bytes. */
            size_t new_cap = (cap == 0) ? OTA_STREAM_INITIAL_CAP : (cap * 2);
            if (new_cap > max_bytes) new_cap = max_bytes;
            if (new_cap <= cap) {
                /* No room to grow but we still need at least 1 byte to
                 * probe TOOBIG.  Allocate exactly max_bytes + 1?  No --
                 * we never want to exceed the cap.  Instead, ask for
                 * 1 byte against current cap and rely on the TOOBIG
                 * check below.  But there's no buffer headroom, so:
                 * we briefly grow to max_bytes + 1 to give us a probe
                 * slot... cleaner: handle the "at-cap, want to probe"
                 * case by reading into a tiny on-stack probe byte. */
                uint8_t probe;
                int n = read_fn(ctx, &probe, 1);
                if (n > 0) {
                    /* Any successful byte past max_bytes is TOOBIG. */
                    if (buf) free_fn(buf);
                    *out_buf = NULL;
                    *out_len = 0;
                    return OTA_STREAM_ERR_TOOBIG;
                }
                if (n == 0) {
                    if (zero_run >= max_zero_retries) break;
                    zero_run++;
                    continue;
                }
                /* n < 0 -> clean EOF at exactly max_bytes -- accept. */
                break;
            }

            uint8_t *new_buf;
            if (buf == NULL) {
                new_buf = (uint8_t *)alloc_fn(new_cap);
            } else {
                new_buf = (uint8_t *)realloc_fn(buf, new_cap);
            }
            if (!new_buf) {
                if (buf) free_fn(buf);
                *out_buf = NULL;
                *out_len = 0;
                return OTA_STREAM_ERR_OOM;
            }
            buf = new_buf;
            cap = new_cap;
        }

        size_t want = cap - used;
        int n = read_fn(ctx, buf + used, want);

        if (n > 0) {
            zero_run = 0;
            /* The callback contract says n <= cap (i.e. n <= want), but be
             * defensive: a misbehaving callback that overflows the buffer
             * would corrupt the heap.  Treat over-fill as TOOBIG. */
            if ((size_t)n > want) {
                if (buf) free_fn(buf);
                *out_buf = NULL;
                *out_len = 0;
                return OTA_STREAM_ERR_TOOBIG;
            }
            used += (size_t)n;
            continue;
        }

        if (n == 0) {
            if (zero_run >= max_zero_retries) break;
            zero_run++;
            continue;
        }

        /* n < 0 : terminal. */
        break;
    }

    if (used == 0) {
        if (buf) free_fn(buf);
        *out_buf = NULL;
        *out_len = 0;
        return OTA_STREAM_ERR_EMPTY;
    }

    *out_buf = buf;
    *out_len = used;
    return OTA_STREAM_OK;
}
