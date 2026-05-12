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
    if (!sb || len == 0) return;

    pthread_mutex_lock(&sb->lock);

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

    if (sb->used + len < sb->cap)
        sb->used += len;
    else
        sb->used = sb->cap;

    pthread_mutex_unlock(&sb->lock);
}

uint8_t *scrollback_get_lines(scrollback_t *sb, int max_lines, size_t *out_len)
{
    if (!sb || !out_len) return NULL;

    pthread_mutex_lock(&sb->lock);
    size_t used = sb->used;
    size_t head = sb->head;
    pthread_mutex_unlock(&sb->lock);

    if (used == 0) {
        *out_len = 0;
        return NULL;
    }

    size_t cap    = sb->cap;   /* immutable after create */
    size_t oldest = (head + cap - used) % cap;

    /* Scan backward to find the start of the last max_lines lines. */
    size_t dump_start_offset = 0;
    int newlines = 0;
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

    size_t dump_len  = used - dump_start_offset;
    size_t start_idx = (oldest + dump_start_offset) % cap;
    size_t to_end    = cap - start_idx;

    uint8_t *out = malloc(dump_len);
    if (!out) {
        *out_len = 0;
        return NULL;
    }

    if (to_end >= dump_len) {
        memcpy(out, sb->buf + start_idx, dump_len);
    } else {
        memcpy(out,          sb->buf + start_idx, to_end);
        memcpy(out + to_end, sb->buf,              dump_len - to_end);
    }

    *out_len = dump_len;
    return out;
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
    if (!sb || len == 0) return;

    xSemaphoreTake(sb->lock, portMAX_DELAY);

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

    if (sb->used + len < sb->cap)
        sb->used += len;
    else
        sb->used = sb->cap;

    xSemaphoreGive(sb->lock);
}

uint8_t *scrollback_get_lines(scrollback_t *sb, int max_lines, size_t *out_len)
{
    if (!sb || !out_len) return NULL;

    /* Snapshot the two mutable fields under lock; everything else is
     * lock-free.  scrollback_push holds the lock only for the duration
     * of its own memcpy (<=64 B from the CDC callback), so contention
     * here is microseconds at most. */
    xSemaphoreTake(sb->lock, portMAX_DELAY);
    size_t used = sb->used;
    size_t head = sb->head;
    xSemaphoreGive(sb->lock);

    if (used == 0) {
        *out_len = 0;
        return NULL;
    }

    size_t cap    = sb->cap;   /* immutable after create */
    size_t oldest = (head + cap - used) % cap;

    /* Scan backward (lock-free) to find the start of the last max_lines
     * lines.  Concurrent pushes may overwrite the oldest bytes we scan,
     * but minor tearing in a debug replay buffer is acceptable. */
    size_t dump_start_offset = 0;
    int newlines = 0;
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

    size_t dump_len  = used - dump_start_offset;
    size_t start_idx = (oldest + dump_start_offset) % cap;
    size_t to_end    = cap - start_idx;

    uint8_t *out = heap_caps_malloc(dump_len,
                                    MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!out)
        out = malloc(dump_len);
    if (!out) {
        *out_len = 0;
        return NULL;
    }

    if (to_end >= dump_len) {
        memcpy(out, sb->buf + start_idx, dump_len);
    } else {
        memcpy(out,          sb->buf + start_idx, to_end);
        memcpy(out + to_end, sb->buf,              dump_len - to_end);
    }

    *out_len = dump_len;
    return out;
}

#endif /* UNIT_TEST / ESP32 */
