/*
 * ring.c — StreamBuffer wrapper (ESP32 target) / pthread (native tests)
 */

#include "ring.h"

#include <stdlib.h>
#include <string.h>

/* ============================================================
 * ESP32 target implementation (FreeRTOS StreamBuffer + PSRAM)
 * ============================================================ */
#ifndef RING_NATIVE

#include "freertos/FreeRTOS.h"
#include "freertos/stream_buffer.h"
#include "esp_heap_caps.h"

struct ring {
    StreamBufferHandle_t sb;
    volatile bool        closed;
};

ring_t *ring_create(size_t capacity)
{
    ring_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;

    /*
     * Allocate the buffer storage in PSRAM (8 MB available on N16R8).
     * xStreamBufferCreateWithCaps is an ESP-IDF extension that places
     * the data region in PSRAM while keeping the control struct in
     * internal RAM (safe during cache-disabled flash operations).
     */
    /* Prefer PSRAM; fall back to internal RAM when PSRAM is absent
     * (e.g. Wokwi simulation with CONFIG_SPIRAM=n). */
    r->sb = xStreamBufferCreateWithCaps(
        capacity,
        /*xTriggerLevelBytes=*/1,
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

    if (!r->sb) {
        r->sb = xStreamBufferCreate(capacity, 1);
    }
    if (!r->sb) {
        free(r);
        return NULL;
    }
    r->closed = false;
    return r;
}

void ring_free(ring_t *r)
{
    if (!r) return;
    vStreamBufferDeleteWithCaps(r->sb);
    free(r);
}

int ring_send(ring_t *r, const uint8_t *buf, size_t len)
{
    size_t remaining = len;
    const uint8_t *p = buf;

    while (remaining > 0) {
        if (r->closed) return -1;

        /*
         * xStreamBufferSend with a finite timeout so we can check
         * the closed flag periodically, while still providing backpressure.
         * Each call writes as many bytes as currently fit.
         */
        size_t sent = xStreamBufferSend(r->sb, p, remaining,
                                        pdMS_TO_TICKS(50));
        p         += sent;
        remaining -= sent;
    }
    return (int)len;
}

int ring_recv(ring_t *r, uint8_t *buf, size_t cap)
{
    while (1) {
        if (r->closed) return -1;

        size_t rxd = xStreamBufferReceive(r->sb, buf, cap,
                                          pdMS_TO_TICKS(50));
        if (rxd > 0) return (int)rxd;
    }
}

void ring_close(ring_t *r)
{
    if (r) r->closed = true;
}

void ring_reopen(ring_t *r)
{
    if (!r) return;
    /* Drain any stale data left from the previous session */
    uint8_t tmp[64];
    while (xStreamBufferReceive(r->sb, tmp, sizeof(tmp), 0) > 0) {}
    r->closed = false;
}

int ring_try_send(ring_t *r, const uint8_t *buf, size_t len)
{
    if (!r || !buf) return -1;
    if (r->closed) return -1;
    if (len == 0) return 0;

    /* xStreamBufferSend with timeout=0: writes what fits, returns immediately */
    size_t sent = xStreamBufferSend(r->sb, buf, len, 0);
    return (int)sent;
}

/* ============================================================
 * Native (host) implementation — pthread mutex + condvar
 * ============================================================ */
#else /* RING_NATIVE */

#include <pthread.h>
#include <assert.h>

struct ring {
    uint8_t         *buf;
    size_t           capacity;
    size_t           head;   /* write index */
    size_t           tail;   /* read index  */
    size_t           used;
    bool             closed;
    pthread_mutex_t  mu;
    pthread_cond_t   not_full;
    pthread_cond_t   not_empty;
};

ring_t *ring_create(size_t capacity)
{
    ring_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;

    r->buf = malloc(capacity);
    if (!r->buf) { free(r); return NULL; }

    r->capacity = capacity;
    r->head     = 0;
    r->tail     = 0;
    r->used     = 0;
    r->closed   = false;

    pthread_mutex_init(&r->mu, NULL);
    pthread_cond_init(&r->not_full,  NULL);
    pthread_cond_init(&r->not_empty, NULL);
    return r;
}

void ring_free(ring_t *r)
{
    if (!r) return;
    pthread_cond_destroy(&r->not_empty);
    pthread_cond_destroy(&r->not_full);
    pthread_mutex_destroy(&r->mu);
    free(r->buf);
    free(r);
}

int ring_send(ring_t *r, const uint8_t *buf, size_t len)
{
    size_t remaining = len;
    const uint8_t *p = buf;

    pthread_mutex_lock(&r->mu);
    while (remaining > 0) {
        while (r->used == r->capacity && !r->closed)
            pthread_cond_wait(&r->not_full, &r->mu);

        if (r->closed) {
            pthread_mutex_unlock(&r->mu);
            return -1;
        }

        size_t space = r->capacity - r->used;
        size_t chunk = remaining < space ? remaining : space;

        /* Handle wrap-around */
        size_t first = r->capacity - r->head;
        if (chunk <= first) {
            memcpy(r->buf + r->head, p, chunk);
            r->head = (r->head + chunk) % r->capacity;
        } else {
            memcpy(r->buf + r->head, p, first);
            memcpy(r->buf, p + first, chunk - first);
            r->head = chunk - first;
        }

        r->used    += chunk;
        p          += chunk;
        remaining  -= chunk;
        pthread_cond_signal(&r->not_empty);
    }
    pthread_mutex_unlock(&r->mu);
    return (int)len;
}

int ring_recv(ring_t *r, uint8_t *buf, size_t cap)
{
    pthread_mutex_lock(&r->mu);
    while (r->used == 0 && !r->closed)
        pthread_cond_wait(&r->not_empty, &r->mu);

    if (r->used == 0 && r->closed) {
        pthread_mutex_unlock(&r->mu);
        return -1;
    }

    size_t chunk = r->used < cap ? r->used : cap;

    /* Handle wrap-around */
    size_t first = r->capacity - r->tail;
    if (chunk <= first) {
        memcpy(buf, r->buf + r->tail, chunk);
        r->tail = (r->tail + chunk) % r->capacity;
    } else {
        memcpy(buf, r->buf + r->tail, first);
        memcpy(buf + first, r->buf, chunk - first);
        r->tail = chunk - first;
    }

    r->used -= chunk;
    pthread_cond_signal(&r->not_full);
    pthread_mutex_unlock(&r->mu);
    return (int)chunk;
}

void ring_close(ring_t *r)
{
    if (!r) return;
    pthread_mutex_lock(&r->mu);
    r->closed = true;
    pthread_cond_broadcast(&r->not_full);
    pthread_cond_broadcast(&r->not_empty);
    pthread_mutex_unlock(&r->mu);
}

void ring_reopen(ring_t *r)
{
    if (!r) return;
    pthread_mutex_lock(&r->mu);
    r->head   = 0;
    r->tail   = 0;
    r->used   = 0;
    r->closed = false;
    pthread_mutex_unlock(&r->mu);
}

int ring_try_send(ring_t *r, const uint8_t *buf, size_t len)
{
    if (!r || !buf) return -1;
    if (len == 0) return 0;

    /* trylock: if the mutex is contended, return 0 (don't block) */
    if (pthread_mutex_trylock(&r->mu) != 0) return 0;

    if (r->closed) {
        pthread_mutex_unlock(&r->mu);
        return -1;
    }

    size_t space = r->capacity - r->used;
    size_t chunk = (len < space) ? len : space;

    if (chunk > 0) {
        /* Write chunk bytes into the ring, handling wrap-around */
        size_t first = r->capacity - r->head;
        if (chunk <= first) {
            memcpy(r->buf + r->head, buf, chunk);
            r->head = (r->head + chunk) % r->capacity;
        } else {
            memcpy(r->buf + r->head, buf, first);
            memcpy(r->buf, buf + first, chunk - first);
            r->head = chunk - first;
        }
        r->used += chunk;
        pthread_cond_signal(&r->not_empty);
    }

    pthread_mutex_unlock(&r->mu);
    return (int)chunk;
}

#endif /* RING_NATIVE */
