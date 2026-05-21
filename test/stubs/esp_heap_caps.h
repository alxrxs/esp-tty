/* Native test stub: esp_heap_caps.h
 *
 * On-device this routes to ESP-IDF heap.  Native host tests just forward to
 * stdlib malloc/calloc/free; the MALLOC_CAP_* flags are ignored.
 */
#pragma once

#include <stdlib.h>
#include <stdint.h>

/* Capability bits (only the ones our code tests actually use) */
#define MALLOC_CAP_EXEC         (1 << 0)
#define MALLOC_CAP_32BIT        (1 << 1)
#define MALLOC_CAP_8BIT         (1 << 2)
#define MALLOC_CAP_DMA          (1 << 3)
#define MALLOC_CAP_SPIRAM       (1 << 4)   /* maps to regular malloc on host */
#define MALLOC_CAP_INTERNAL     (1 << 5)
#define MALLOC_CAP_DEFAULT      (1 << 6)
#define MALLOC_CAP_IRAM_8BIT    (1 << 7)
#define MALLOC_CAP_RETENTION    (1 << 8)
#define MALLOC_CAP_RTCRAM       (1 << 9)
#define MALLOC_CAP_TCM          (1 << 10)
#define MALLOC_CAP_INVALID      (1 << 31)

static inline void *heap_caps_malloc(size_t size, uint32_t caps)
{
    (void)caps;
    return malloc(size);
}

static inline void *heap_caps_calloc(size_t n, size_t size, uint32_t caps)
{
    (void)caps;
    return calloc(n, size);
}

static inline void *heap_caps_realloc(void *ptr, size_t size, uint32_t caps)
{
    (void)caps;
    return realloc(ptr, size);
}

static inline void heap_caps_free(void *ptr)
{
    free(ptr);
}

static inline size_t heap_caps_get_free_size(uint32_t caps)
{
    (void)caps;
    return SIZE_MAX;   /* "unlimited" on host */
}
