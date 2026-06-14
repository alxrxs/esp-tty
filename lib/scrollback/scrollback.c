/*
 * scrollback.c -- Circular USB-output scrollback buffer
 */

#include "scrollback.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* -- Shared pure formatters (compiled on both native and ESP32) ----------- */

const char SCROLLBACK_FOOTER[] = "\x1b[2m--- live ---\x1b[0m\r\n";

int scrollback_count_newlines(const uint8_t *buf, size_t len)
{
    if (!buf || len == 0) return 0;
    int n = 0;
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\n') n++;
    return n;
}

int scrollback_format_header(int line_count, char *out, size_t out_sz)
{
    if (line_count < 0)  return 0;
    if (out == NULL)     return 0;
    if (out_sz == 0)     return 0;

    /* snprintf returns the number of bytes that *would* have been written
     * (excluding the NUL), regardless of truncation.  If that count is >=
     * out_sz, the buffer was too small -- return 0 so the caller doesn't
     * emit a half-formed escape sequence. */
    int n = snprintf(out, out_sz,
                     "\r\n\x1b[2m--- scrollback: %d lines ---\x1b[0m\r\n",
                     line_count);

    if (n <= 0)              return 0;  /* encoding error (should not happen) */
    if ((size_t)n >= out_sz) return 0;  /* truncated -- no room for NUL */

    return n;
}

/* -- Platform shims ------------------------------------------------------- */

#ifdef UNIT_TEST

/* Native host tests: real circular-buffer implementation backed by
 * malloc + pthread_mutex_t (same pattern as ring.c's RING_NATIVE block). */

#include <pthread.h>

struct scrollback_t {
    uint8_t         *buf;   /* circular storage, cap bytes */
    size_t           cap;
    size_t           head;  /* index of next write slot */
    size_t           used;  /* bytes currently stored (0 .. cap) */
    pthread_mutex_t  lock;
};

scrollback_t *scrollback_create(size_t cap)
{
    if (cap == 0) return NULL;
    scrollback_t *sb = calloc(1, sizeof(*sb));
    if (!sb) return NULL;

    sb->buf = malloc(cap);
    if (!sb->buf) { free(sb); return NULL; }

    sb->cap  = cap;
    sb->head = 0;
    sb->used = 0;
    pthread_mutex_init(&sb->lock, NULL);
    return sb;
}

void scrollback_push(scrollback_t *sb, const uint8_t *data, size_t len)
{
    if (!sb || !data || len == 0) return;

    /* Mirror the ESP32 contract: NON-BLOCKING try-lock.  If a concurrent
     * scrollback_get_lines holds the lock, drop this chunk rather than block.
     * pthread_mutex_trylock returns 0 on success, non-zero (EBUSY) when held. */
    if (pthread_mutex_trylock(&sb->lock) != 0) return;

    /* Write into the circular buffer, wrapping as needed. */
    size_t rem = len;
    const uint8_t *p = data;
    while (rem > 0) {
        size_t space_to_end = sb->cap - sb->head;
        size_t take = (rem < space_to_end) ? rem : space_to_end;
        memcpy(sb->buf + sb->head, p, take);
        sb->head = (sb->head + take) % sb->cap;
        p   += take;
        rem -= take;
    }

    /* Bound check arranged so size_t never overflows even for absurd len. */
    if (len < sb->cap - sb->used)
        sb->used += len;
    else
        sb->used = sb->cap;

    pthread_mutex_unlock(&sb->lock);
}

void scrollback_destroy(scrollback_t *sb)
{
    if (!sb) return;
    pthread_mutex_destroy(&sb->lock);
    free(sb->buf);
    free(sb);
}

/*
 * Scan backward through the last max_lines lines and return the byte length
 * of the dump (used - dump_start_offset).  Caller must hold sb->lock.  Sets
 * *out_start_idx to the absolute ring index where the dump begins.
 */
static size_t scrollback_scan_locked(const scrollback_t *sb, int max_lines,
                                     size_t *out_start_idx)
{
    size_t used   = sb->used;
    size_t cap    = sb->cap;   /* immutable after create */
    size_t oldest = (sb->head + cap - used) % cap;

    size_t dump_start_offset = 0;
    int    newlines = 0;
    size_t i = used;
    while (i > 0) {
        i--;
        if (sb->buf[(oldest + i) % cap] == '\n') {
            newlines++;
            if (newlines > max_lines) {
                dump_start_offset = i + 1; /* start after this \n */
                break;
            }
        }
    }

    *out_start_idx = (oldest + dump_start_offset) % cap;
    return used - dump_start_offset;
}

uint8_t *scrollback_get_lines(scrollback_t *sb, int max_lines, size_t *out_len)
{
    if (!sb || !out_len) return NULL;

    /* max_lines == 0 means "no lines" -- return empty immediately. */
    if (max_lines <= 0) {
        *out_len = 0;
        return NULL;
    }

    /* The allocation is deliberately NOT performed under sb->lock so the
     * critical section (and therefore the window during which a try-locking
     * scrollback_push would have to drop data) stays minimal.  We measure the
     * dump length under the lock, allocate outside it, then re-take the lock
     * to copy -- retrying with a larger buffer if a concurrent push grew the
     * data in between.  Mirrors the ESP32 implementation exactly. */
    uint8_t *out = NULL;
    size_t   alloc_len = 0;

    for (;;) {
        pthread_mutex_lock(&sb->lock);
        size_t start_idx = 0;
        size_t dump_len = (sb->used == 0)
            ? 0
            : scrollback_scan_locked(sb, max_lines, &start_idx);

        if (dump_len == 0) {
            pthread_mutex_unlock(&sb->lock);
            free(out);
            *out_len = 0;
            return NULL;
        }

        if (out && dump_len <= alloc_len) {
            size_t cap    = sb->cap;
            size_t to_end = cap - start_idx;
            if (to_end >= dump_len) {
                memcpy(out, sb->buf + start_idx, dump_len);
            } else {
                memcpy(out,          sb->buf + start_idx, to_end);
                memcpy(out + to_end, sb->buf,              dump_len - to_end);
            }
            pthread_mutex_unlock(&sb->lock);
            *out_len = dump_len;
            return out;
        }

        size_t need = dump_len;
        pthread_mutex_unlock(&sb->lock);

        free(out);   /* free(NULL) is a no-op on the first iteration */
        out = malloc(need);
        if (!out) {
            *out_len = 0;
            return NULL;
        }
        alloc_len = need;
    }
}

/* Test-only mutex hooks -- see scrollback.h. */
void scrollback_test_lock(scrollback_t *sb)
{
    if (sb) pthread_mutex_lock(&sb->lock);
}

void scrollback_test_unlock(scrollback_t *sb)
{
    if (sb) pthread_mutex_unlock(&sb->lock);
}

#else /* ESP32 target */

#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

struct scrollback_t {
    uint8_t          *buf;  /* circular storage, cap bytes, in PSRAM */
    size_t            cap;
    size_t            head; /* index of next write slot */
    size_t            used; /* bytes currently stored (0 .. cap) */
    SemaphoreHandle_t lock;
};

scrollback_t *scrollback_create(size_t cap)
{
    scrollback_t *sb = calloc(1, sizeof(*sb));
    if (!sb) return NULL;

    /* Prefer PSRAM; fall back to internal RAM (Wokwi lacks PSRAM). */
    sb->buf = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!sb->buf)
        sb->buf = malloc(cap);
    if (!sb->buf) {
        free(sb);
        return NULL;
    }

    sb->cap  = cap;
    sb->head = 0;
    sb->used = 0;
    sb->lock = xSemaphoreCreateMutex();
    if (!sb->lock) {
        free(sb->buf);
        free(sb);
        return NULL;
    }
    return sb;
}

void scrollback_push(scrollback_t *sb, const uint8_t *data, size_t len)
{
    if (!sb || !data || len == 0) return;

    /* Contract (see scrollback.h): this call is NON-BLOCKING and safe to run
     * from the TinyUSB CDC RX callback context.  scrollback_get_lines holds
     * sb->lock for a full scan + (up to 128 KB) memcpy during SSH-connect
     * replay; a portMAX_DELAY take here would stall the USB task for the whole
     * dump.  Use a try-lock (timeout 0) and silently drop this chunk if the
     * lock is momentarily held -- the dropped bytes are merely absent from the
     * scrollback ring, which is benign. */
    if (xSemaphoreTake(sb->lock, 0) != pdTRUE) return;

    /* Write into the circular buffer, wrapping as needed. */
    size_t rem = len;
    const uint8_t *p = data;
    while (rem > 0) {
        size_t space_to_end = sb->cap - sb->head;
        size_t take = (rem < space_to_end) ? rem : space_to_end;
        memcpy(sb->buf + sb->head, p, take);
        sb->head = (sb->head + take) % sb->cap;
        p   += take;
        rem -= take;
    }

    /* Bound check arranged so size_t never overflows even for absurd len. */
    if (len < sb->cap - sb->used)
        sb->used += len;
    else
        sb->used = sb->cap;

    xSemaphoreGive(sb->lock);
}

void scrollback_destroy(scrollback_t *sb)
{
    if (!sb) return;
    vSemaphoreDelete(sb->lock);
    free(sb->buf);
    free(sb);
}

/*
 * Scan backward through the last max_lines lines and return the byte length
 * of the dump (used - dump_start_offset).  Caller must hold sb->lock.  Sets
 * *out_start_idx to the absolute ring index where the dump begins.
 */
static size_t scrollback_scan_locked(const scrollback_t *sb, int max_lines,
                                     size_t *out_start_idx)
{
    size_t used   = sb->used;
    size_t cap    = sb->cap;   /* immutable after create */
    size_t oldest = (sb->head + cap - used) % cap;

    size_t dump_start_offset = 0;
    int    newlines = 0;
    size_t i = used;
    while (i > 0) {
        i--;
        if (sb->buf[(oldest + i) % cap] == '\n') {
            newlines++;
            if (newlines > max_lines) {
                dump_start_offset = i + 1; /* start after this \n */
                break;
            }
        }
    }

    *out_start_idx = (oldest + dump_start_offset) % cap;
    return used - dump_start_offset;
}

uint8_t *scrollback_get_lines(scrollback_t *sb, int max_lines, size_t *out_len)
{
    if (!sb || !out_len) return NULL;

    /* max_lines == 0 means "no lines" -- return empty immediately. */
    if (max_lines <= 0) {
        *out_len = 0;
        return NULL;
    }

    /* The allocation (up to SCROLLBACK_DEFAULT_CAP, 128 KB) is deliberately
     * NOT performed under sb->lock: doing so would extend the critical section
     * by the duration of a PSRAM heap walk and stall scrollback_push (which
     * runs in the TinyUSB callback context and only try-locks).  Instead we
     *   1. take the lock, measure the dump length, release it;
     *   2. allocate outside the lock;
     *   3. re-take the lock and re-measure.
     * A concurrent push may have changed head/used between (1) and (3); if the
     * dump grew past what we allocated we free and retry with the larger size.
     * The retry count is bounded in practice because each push is a single
     * CDC chunk while the alloc completes in microseconds. */
    uint8_t *out = NULL;
    size_t   alloc_len = 0;

    for (;;) {
        xSemaphoreTake(sb->lock, portMAX_DELAY);
        size_t start_idx = 0;
        size_t dump_len = (sb->used == 0)
            ? 0
            : scrollback_scan_locked(sb, max_lines, &start_idx);

        if (dump_len == 0) {
            xSemaphoreGive(sb->lock);
            free(out);
            *out_len = 0;
            return NULL;
        }

        /* If we already hold a buffer big enough, copy now and finish. */
        if (out && dump_len <= alloc_len) {
            size_t cap    = sb->cap;
            size_t to_end = cap - start_idx;
            if (to_end >= dump_len) {
                memcpy(out, sb->buf + start_idx, dump_len);
            } else {
                memcpy(out,          sb->buf + start_idx, to_end);
                memcpy(out + to_end, sb->buf,              dump_len - to_end);
            }
            xSemaphoreGive(sb->lock);
            *out_len = dump_len;
            return out;
        }

        /* Need a (bigger) buffer: drop the lock before allocating. */
        size_t need = dump_len;
        xSemaphoreGive(sb->lock);

        free(out);   /* free(NULL) is a no-op on the first iteration */
        out = heap_caps_malloc(need, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (!out)
            out = malloc(need);
        if (!out) {
            *out_len = 0;
            return NULL;
        }
        alloc_len = need;
    }
}

#endif /* UNIT_TEST / ESP32 */
